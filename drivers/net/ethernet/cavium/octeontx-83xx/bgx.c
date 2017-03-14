/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/random.h>

#include "../thunder/thunder_bgx.h"
#include "../thunder/nic.h"
#include "bgx.h"

#define BGX_LMAC_NUM_CHANS 16
#define BGX_LMAC_BASE_CHAN(__bgx, __lmac) \
	(0x800 | ((__bgx) << 8) | ((__lmac) << 4)) /* PKI_CHAN_E */

#define BGX_INVALID_ID	(-1)

/* BGX CSRs (offsets from the PF base address for particular BGX:LMAC).
 * NOTE: Most of the CSR definitions are provided in thunder_bgx.h.
 * Here, only missing registers or those, which do not match OCTEONTX
 * definions in HRM.
 * TODO: Consider to provide here a full list of CSRs and use them instead
 * of those in the thunder driver.
 */
#define BGX_CMR_CONFIG			0x0
#define BGX_CMR_GLOBAL_CONFIG		0x8
#define BGX_CMR_RX_BP_STATUS		0xF0
#define BGX_CMR_RX_DMAC_CAM(__dmac)	(0x200 + ((__dmac) * 0x8))

/* BGX device Configuration and Control Block */
struct bgxpf {
	struct list_head list; /* List of BGX devices */
	void __iomem *reg_base;
	int node; /* CPU node */
	int bgx_idx; /* CPU-local BGX device index.*/
	int lmac_count;
};

/* Global lists of LBK devices and ports */
static DEFINE_SPINLOCK(octeontx_bgx_lock);
static LIST_HEAD(octeontx_bgx_devices);
static LIST_HEAD(octeontx_bgx_ports);

/* Interface with the thunder driver */
static struct thunder_bgx_com_s *thbgx;

static struct bgxpf *get_bgx_dev(int node, int bgx_idx)
{
	struct bgxpf *dev;

	list_for_each_entry(dev, &octeontx_bgx_devices, list) {
		if (dev->node == node && dev->bgx_idx == bgx_idx)
			return dev;
	}
	return NULL;
}

static struct octtx_bgx_port *get_bgx_port(int domain_id, int port_idx)
{
	struct octtx_bgx_port *port;

	spin_lock(&octeontx_bgx_lock);
	list_for_each_entry(port, &octeontx_bgx_ports, list) {
		if (port->domain_id == domain_id &&
		    port->dom_port_idx == port_idx) {
			spin_unlock(&octeontx_bgx_lock);
			return port;
		}
	}
	spin_unlock(&octeontx_bgx_lock);
	return NULL;
}

static void bgx_reg_write(struct bgxpf *bgx, u64 lmac, u64 offset, u64 val)
{
	writeq_relaxed(val, bgx->reg_base + (lmac << 20) + offset);
}

static u64 bgx_reg_read(struct bgxpf *bgx, u64 lmac, u64 offset)
{
	return readq_relaxed(bgx->reg_base + (lmac << 20) + offset);
}

/* BGX Interface functions.
 */
static int bgx_get_num_ports(int node)
{
	struct octtx_bgx_port *port;
	int count = 0;

	spin_lock(&octeontx_bgx_lock);
	list_for_each_entry(port, &octeontx_bgx_ports, list) {
		if (port->node == node)
			count++;
	}
	spin_unlock(&octeontx_bgx_lock);
	return count;
}

static int bgx_get_link_status(int node, int bgx, int lmac)
{
	struct bgx_link_status link;

	thbgx->get_link_status(node, bgx, lmac, &link);
	return link.link_up;
}

static struct octtx_bgx_port *bgx_get_port_by_chan(int node, u16 domain_id,
						   int chan)
{
	struct octtx_bgx_port *port;
	int max_chan;

	spin_lock(&octeontx_bgx_lock);
	list_for_each_entry(port, &octeontx_bgx_ports, list) {
		if (port->domain_id == BGX_INVALID_ID ||
		    port->domain_id != domain_id ||
				port->node != node)
			continue;
		max_chan = port->base_chan + port->num_chans;
		if (chan >= port->base_chan && chan < max_chan) {
			spin_unlock(&octeontx_bgx_lock);
			return port;
		}
	}
	spin_unlock(&octeontx_bgx_lock);
	return NULL;
}

/* Main MBOX message processing function.
 */
static int bgx_port_open(struct octtx_bgx_port *port);
static int bgx_port_close(struct octtx_bgx_port *port);
static int bgx_port_start(struct octtx_bgx_port *port);
static int bgx_port_stop(struct octtx_bgx_port *port);
static int bgx_port_config(struct octtx_bgx_port *port,
			   mbox_bgx_port_conf_t *conf);
static int bgx_port_status(struct octtx_bgx_port *port,
			   mbox_bgx_port_status_t *stat);
static int bgx_port_stats_get(struct octtx_bgx_port *port,
			      mbox_bgx_port_stats_t *stat);
static int bgx_port_stats_clr(struct octtx_bgx_port *port);
static int bgx_port_link_status(struct octtx_bgx_port *port, u8 *up);
static int bgx_port_promisc_set(struct octtx_bgx_port *port, u8 on);
static int bgx_port_macaddr_set(struct octtx_bgx_port *port, u8 macaddr[]);
static int bgx_port_bp_set(struct octtx_bgx_port *port, u8 on);
static int bgx_port_bcast_set(struct octtx_bgx_port *port, u8 on);
static int bgx_port_mcast_set(struct octtx_bgx_port *port, u8 on);
static int bgx_port_mtu_set(struct octtx_bgx_port *port, u16 mtu);

static int bgx_receive_message(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp, void *mdata)
{
	struct octtx_bgx_port *port;

	if (!mdata)
		return -ENOMEM;
	port = get_bgx_port(domain_id, hdr->vfid);
	if (!port) {
		hdr->res_code = MBOX_RET_INVALID;
		return -ENODEV;
	}
	switch (hdr->msg) {
	case MBOX_BGX_PORT_OPEN:
		bgx_port_open(port);
		bgx_port_config(port, mdata);
		resp->data = sizeof(mbox_bgx_port_conf_t);
		break;
	case MBOX_BGX_PORT_CLOSE:
		bgx_port_close(port);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_START:
		bgx_port_start(port);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_STOP:
		bgx_port_stop(port);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_GET_CONFIG:
		bgx_port_config(port, mdata);
		resp->data = sizeof(mbox_bgx_port_conf_t);
		break;
	case MBOX_BGX_PORT_GET_STATUS:
		bgx_port_status(port, mdata);
		resp->data = sizeof(mbox_bgx_port_status_t);
		break;
	case MBOX_BGX_PORT_GET_STATS:
		bgx_port_stats_get(port, mdata);
		resp->data = sizeof(mbox_bgx_port_stats_t);
		break;
	case MBOX_BGX_PORT_CLR_STATS:
		bgx_port_stats_clr(port);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_GET_LINK_STATUS:
		bgx_port_link_status(port, mdata);
		resp->data = sizeof(u8);
		break;
	case MBOX_BGX_PORT_SET_PROMISC:
		bgx_port_promisc_set(port, *(u8 *)mdata);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_SET_MACADDR:
		bgx_port_macaddr_set(port, mdata);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_SET_BP:
		bgx_port_bp_set(port, *(u8 *)mdata);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_SET_BCAST:
		bgx_port_bcast_set(port, *(u8 *)mdata);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_SET_MCAST:
		bgx_port_mcast_set(port, *(u8 *)mdata);
		resp->data = 0;
		break;
	case MBOX_BGX_PORT_SET_MTU:
		bgx_port_mtu_set(port, *(u16 *)mdata);
		resp->data = 0;
		break;
	default:
		hdr->res_code = MBOX_RET_INVALID;
		return -EINVAL;
	}
	hdr->res_code = MBOX_RET_SUCCESS;
	return 0;
}

/* MBOX message processing support functions.
 */
int bgx_port_open(struct octtx_bgx_port *port)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;

	/* Stop the port first:*/
	bgx_port_stop(port);

	/* Route packet data to/from PKI/PKO: */
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMR_CONFIG);
	reg |= CMR_X2P_SELECT_PKI | CMR_P2X_SELECT_PKO;
	bgx_reg_write(bgx, port->lmac, BGX_CMR_CONFIG, reg);

	/* Setup PKI port (pkind): */
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_ID_MAP, port->pkind);
	return 0;
}

int bgx_port_close(struct octtx_bgx_port *port)
{
	struct bgxpf *bgx;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	/* Park the BGX output to the PKI port 0: */
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_ID_MAP, 0);
	return 0;
}

int bgx_port_start(struct octtx_bgx_port *port)
{
	thbgx->enable(port->node, port->bgx, port->lmac);
	return 0;
}

int bgx_port_stop(struct octtx_bgx_port *port)
{
	thbgx->disable(port->node, port->bgx, port->lmac);
	return 0;
}

int bgx_port_config(struct octtx_bgx_port *port, mbox_bgx_port_conf_t *conf)
{
	struct bgxpf *bgx;
	const u8 *macaddr;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	conf->node = port->node;
	conf->bgx = port->bgx;
	conf->lmac = port->lmac;
	conf->base_chan = port->base_chan;
	conf->num_chans = port->num_chans;

	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_ID_MAP);
	conf->pkind = reg & 0x3F; /* PKND */

	reg = bgx_reg_read(bgx, port->lmac, BGX_CMR_CONFIG);
	conf->mode = (reg >> 8) & 0x7; /* LMAC_TYPE */
	conf->enable = (reg & CMR_PKT_TX_EN) &&
			(reg & CMR_PKT_RX_EN) && (reg & CMR_EN);

	reg = bgx_reg_read(bgx, 0, BGX_CMR_GLOBAL_CONFIG);
	conf->fcs_strip = (reg >> 6) & 0x1; /* FCS_STRIP */

	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL);
	conf->bcast_mode = reg & 0x1; /* BCAST_ACCEPT */
	conf->mcast_mode = (reg >> 1) & 0x3; /* MCAST_MODE */

	macaddr = thbgx->get_mac_addr(port->node, port->bgx, port->lmac);
	memcpy(conf->macaddr, macaddr, 6);

	switch (conf->mode) {
	case OCTTX_BGX_LMAC_TYPE_SGMII:
	case OCTTX_BGX_LMAC_TYPE_QSGMII:
		reg = bgx_reg_read(bgx, port->lmac, BGX_GMP_GMI_RXX_JABBER);
		conf->mtu = reg & 0xFFFF;
		break;
	case OCTTX_BGX_LMAC_TYPE_XAUI:
	case OCTTX_BGX_LMAC_TYPE_RXAUI:
	case OCTTX_BGX_LMAC_TYPE_10GR:
	case OCTTX_BGX_LMAC_TYPE_40GR:
		reg = bgx_reg_read(bgx, port->lmac, BGX_SMUX_RX_JABBER);
		conf->mtu = reg & 0xFFFF;
		break;
	}
	return 0;
}

int bgx_port_status(struct octtx_bgx_port *port, mbox_bgx_port_status_t *stat)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMR_RX_BP_STATUS);
	stat->bp = reg & 0x1; /* BP */
	stat->link_up = bgx_get_link_status(port->node, port->bgx, port->lmac);
	return 0;
}

int bgx_port_stats_get(struct octtx_bgx_port *port,
		       mbox_bgx_port_stats_t *stats)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	memset(stats, 0, sizeof(mbox_bgx_port_stats_t));
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_STAT0);
	stats->rx_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_STAT1);
	stats->rx_bytes = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_STAT4);
	stats->rx_dropped = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_STAT6);
	stats->rx_dropped += reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_STAT8);
	stats->rx_errors = reg;
	reg = bgx_reg_read(bgx, 0, BGX_CMRX_RX_STAT9);
	stats->rx_dropped += reg;

	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT0);
	stats->tx_dropped = reg;
	stats->collisions = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT2);
	stats->collisions += reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT3);
	stats->collisions += reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT4);
	stats->tx_bytes = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT5);
	stats->tx_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT6);
	stats->tx_1_to_64_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT7);
	stats->tx_1_to_64_packets += reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT8);
	stats->tx_65_to_127_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT9);
	stats->tx_128_to_255_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT10);
	stats->tx_256_to_511_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT11);
	stats->tx_512_to_1023_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT12);
	stats->tx_1024_to_1522_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT13);
	stats->tx_1523_to_max_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT14);
	stats->tx_broadcast_packets = reg;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_TX_STAT15);
	stats->tx_multicast_packets = reg;
	return 0;
}

int bgx_port_stats_clr(struct octtx_bgx_port *port)
{
	struct bgxpf *bgx;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT0, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT1, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT2, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT3, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT4, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT5, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT6, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT7, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_STAT8, 0);
	bgx_reg_write(bgx, 0, BGX_CMRX_RX_STAT9, 0);
	bgx_reg_write(bgx, 0, BGX_CMRX_RX_STAT10, 0);

	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT0, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT1, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT2, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT3, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT4, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT5, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT6, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT7, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT8, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT9, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT10, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT11, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT12, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT13, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT14, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT15, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT16, 0);
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_TX_STAT17, 0);
	return 0;
}

int bgx_port_link_status(struct octtx_bgx_port *port, u8 *up)
{
	*up = bgx_get_link_status(port->node, port->bgx, port->lmac);
	return 0;
}

int bgx_port_promisc_set(struct octtx_bgx_port *port, u8 on)
{
	struct bgxpf *bgx;
	u64 reg;
	int i;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;

	if (on) { /* Enable */
		/* CAM_ACCEPT = 0 */
		reg = 0x1; /* BCAST_ACCEPT = 1 */
		reg |= 0x1ull << 1; /* MCAST_MODE = 1 */
		bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL, reg);

		for (i = 0; i < 32; i++) {
			reg = bgx_reg_read(bgx, 0, BGX_CMR_RX_DMAC_CAM(i));
			if (((reg >> 49) & 0x3)/* ID */ == port->lmac)
				reg &= ~(0x1ull << 48); /* EN = 0*/
			bgx_reg_write(bgx, 0, BGX_CMR_RX_DMAC_CAM(i), reg);
		}
	} else { /* Disable = enable packet filtering */
		reg = 0x1ull << 3; /* CAM_ACCEPT = 1 */
		reg |= 0x1ull << 1; /* MCAST_MODE = 1 */
		reg |= 0x1; /* BCAST_ACCEPT = 1 */
		bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL, reg);

		for (i = 0; i < 32; i++) {
			reg = bgx_reg_read(bgx, 0, BGX_CMR_RX_DMAC_CAM(i));
			if (((reg >> 49) & 0x3)/* ID */ == port->lmac)
				reg |= 0x1ull << 48; /* EN = 1 */
			bgx_reg_write(bgx, 0, BGX_CMR_RX_DMAC_CAM(i), reg);
		}
	}
	return 0;
}

int bgx_port_macaddr_set(struct octtx_bgx_port *port, u8 macaddr[])
{
	thbgx->set_mac_addr(port->node, port->bgx, port->lmac, macaddr);
	return 0;
}

int bgx_port_bp_set(struct octtx_bgx_port *port, u8 on)
{
	struct bgxpf *bgx;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	/* TODO */
	return 0;
}

int bgx_port_bcast_set(struct octtx_bgx_port *port, u8 on)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL);
	if (on)
		reg |= 0x1; /* BCAST_ACCEPT = 1 */
	else
		reg &= ~0x1; /* BCAST_ACCEPT = 0 */
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL, reg);
	return 0;
}

int bgx_port_mcast_set(struct octtx_bgx_port *port, u8 on)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;
	reg = bgx_reg_read(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL);
	if (on)
		reg |= (1ull << 1) & 0x3; /* MCAST_MODE = 1 */
	else
		reg &= ~(0x3ull << 1); /* MCAST_MODE = 0 */
	bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_DMAC_CTL, reg);
	return 0;
}

int bgx_port_mtu_set(struct octtx_bgx_port *port, u16 mtu)
{
	struct bgxpf *bgx;
	u64 reg;

	bgx = get_bgx_dev(port->node, port->bgx);
	if (!bgx)
		return -EINVAL;

	reg = bgx_reg_read(bgx, port->lmac, BGX_CMR_CONFIG);
	reg = (reg >> 8) & 0x7; /* LMAC_TYPE */

	switch (reg) {
	case OCTTX_BGX_LMAC_TYPE_SGMII:
	case OCTTX_BGX_LMAC_TYPE_QSGMII:
		bgx_reg_write(bgx, port->lmac, BGX_GMP_GMI_RXX_JABBER, mtu);
		break;
	case OCTTX_BGX_LMAC_TYPE_XAUI:
	case OCTTX_BGX_LMAC_TYPE_RXAUI:
	case OCTTX_BGX_LMAC_TYPE_10GR:
	case OCTTX_BGX_LMAC_TYPE_40GR:
		bgx_reg_write(bgx, port->lmac, BGX_SMUX_RX_JABBER, mtu);
		break;
	}
	return 0;
}

/* Domain create function.
 */
static int bgx_create_domain(u32 id, u16 domain_id,
			     struct octtx_bgx_port *port_tbl, int ports,
		struct octeontx_master_com_t *com, void *domain)
{
	struct octtx_bgx_port *port, *gport;
	struct bgxpf *bgx;
	int port_idx;

	/* For each domain port, find requested entry in the list of
	 * global ports and sync up those two port structures.
	 */
	spin_lock(&octeontx_bgx_lock);
	for (port_idx = 0; port_idx < ports; port_idx++) {
		port = &port_tbl[port_idx];

		list_for_each_entry(gport, &octeontx_bgx_ports, list) {
			if (gport->node != id)
				continue;
			if (gport->glb_port_idx != port->glb_port_idx)
				continue;
			/* Check for conflicts with other domains. */
			if (gport->domain_id != BGX_INVALID_ID) {
				spin_unlock(&octeontx_bgx_lock);
				return -EINVAL;
			}
			/* Domain port: */
			port->node = gport->node;
			port->bgx = gport->bgx;
			port->lmac = gport->lmac;
			port->lmac_type = gport->lmac_type;
			port->base_chan = gport->base_chan;
			port->num_chans = gport->num_chans;
			/* Global port: */
			gport->domain_id = domain_id;
			gport->dom_port_idx = port_idx;
			/* Hardware: */
			bgx = get_bgx_dev(port->node, port->bgx);
			bgx_reg_write(bgx, port->lmac,
				      BGX_CMRX_RX_ID_MAP, 0);
		}
	}
	spin_unlock(&octeontx_bgx_lock);
	return 0;
}

/* Domain destroy function.
 */
static int bgx_destroy_domain(u32 id, u16 domain_id)
{
	struct octtx_bgx_port *port;
	struct bgxpf *bgx;

	spin_lock(&octeontx_bgx_lock);
	list_for_each_entry(port, &octeontx_bgx_ports, list) {
		if (port->node == id && port->domain_id == domain_id) {
			port->domain_id = BGX_INVALID_ID;
			port->dom_port_idx = BGX_INVALID_ID;

			bgx = get_bgx_dev(port->node, port->bgx);
			bgx_reg_write(bgx, port->lmac, BGX_CMRX_RX_ID_MAP, 0);
		}
	}
	spin_unlock(&octeontx_bgx_lock);
	return 0;
}

/* Domain reset function.
 */
static int bgx_reset_domain(u32 id, u16 domain_id)
{
	struct octtx_bgx_port *port;

	spin_lock(&octeontx_bgx_lock);
	list_for_each_entry(port, &octeontx_bgx_ports, list) {
		if (port->node == id && port->domain_id == domain_id)
			bgx_port_stop(port);
	}
	spin_unlock(&octeontx_bgx_lock);
	return 0;
}

/* Set pkind for a given port.
 */
static int bgx_set_pkind(u32 id, u16 domain_id, int port, int pkind)
{
	struct octtx_bgx_port *gport;

	gport = get_bgx_port(domain_id, port);
	if (!gport)
		return -EINVAL;
	/* Domain port: */
	gport->pkind = pkind;

	return 0;
}

/* Interface with the main OCTEONTX driver.
 */
struct bgx_com_s bgx_com  = {
	.create_domain = bgx_create_domain,
	.free_domain = bgx_destroy_domain,
	.reset_domain = bgx_reset_domain,
	.receive_message = bgx_receive_message,
	.get_num_ports = bgx_get_num_ports,
	.get_link_status = bgx_get_link_status,
	.get_port_by_chan = bgx_get_port_by_chan,
	.set_pkind = bgx_set_pkind
};
EXPORT_SYMBOL(bgx_com);

/* BGX "octeontx" driver specific initialization.
 * NOTE: The primiary BGX driver startup and initialization is performed
 * in the "thunder" driver.
 */
struct bgx_com_s *bgx_octeontx_init(void)
{
	struct octtx_bgx_port *port;
	struct bgxpf *bgx = NULL;
	u64 bgx_map;
	int bgx_idx;
	int lmac_idx;
	int port_count = 0;
	int node = 0;
	u64 iobase, iosize, reg;

	thbgx = try_then_request_module(symbol_get(thunder_bgx_com),
					"thunder_bgx");
	if (!thbgx)
		return NULL;

	bgx_map = thbgx->get_bgx_count(node);

	for_each_set_bit(bgx_idx, (unsigned long *)&bgx_map,
			 sizeof(bgx_map) * 8) {
		iobase = thbgx->get_reg_base(node, bgx_idx, &iosize);
		if (iobase == 0)
			goto error_handler;

		bgx = kzalloc(sizeof(*bgx), GFP_KERNEL);
		if (!bgx)
			goto error_handler;

		bgx->reg_base = ioremap(iobase, iosize);
		if (!bgx->reg_base)
			goto error_handler;

		bgx->lmac_count = thbgx->get_lmac_count(node, bgx_idx);
		bgx->node = node;
		bgx->bgx_idx = bgx_idx;
		INIT_LIST_HEAD(&bgx->list);
		list_add(&bgx->list, &octeontx_bgx_devices);

		for (lmac_idx = 0; lmac_idx < bgx->lmac_count; lmac_idx++) {
			port = kzalloc(sizeof(*port), GFP_KERNEL);
			if (!port)
				goto error_handler;
			port->glb_port_idx = port_count;
			port->node = node;
			port->bgx = bgx_idx;
			port->lmac = lmac_idx;
			port->base_chan = BGX_LMAC_BASE_CHAN(bgx_idx, lmac_idx);
			port->num_chans = BGX_LMAC_NUM_CHANS;
			port->domain_id = BGX_INVALID_ID;
			port->dom_port_idx = BGX_INVALID_ID;
			reg = bgx_reg_read(bgx, lmac_idx, BGX_CMR_CONFIG);
			port->lmac_type = (reg >> 8) & 0x7; /* LMAC_TYPE */
			if (port->lmac_type == OCTTX_BGX_LMAC_TYPE_40GR)
				reg = 0x100;
			else
				reg = 0x20;
			bgx_reg_write(bgx, lmac_idx, BGX_SMUX_TX_THRESH, reg);

			INIT_LIST_HEAD(&port->list);
			list_add(&port->list, &octeontx_bgx_ports);
			port_count++;
		}
	}
	return &bgx_com;

error_handler:
	symbol_put(thunder_bgx_com);
	kfree(bgx);
	return NULL;
}

