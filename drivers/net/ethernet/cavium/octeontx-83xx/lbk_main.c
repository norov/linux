/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/random.h>

#include "../thunder/thunder_lbk.h"
#include "lbk.h"

#define DRV_NAME "octeontx-lbk"
#define DRV_VERSION "0.1"

/* LBK PCI Device ID (See PCC_DEV_IDL_E in HRM) */
#define PCI_DEVICE_ID_OCTEONTX_LBK 0xA042

#define PCI_LBK_CFG_BAR		0
#define PCI_LBK_MSIX_BAR	4
#define LBK_MSIX_COUNT		1
#define LBK_NODE_SHIFT		2
#define LBK_DEV_PER_CPU		BIT(LBK_NODE_SHIFT)
#define LBK_DEV_MASK		(LBK_DEV_PER_CPU - 1)
#define LBK_MAX_PORTS		(2 * OCTTX_MAX_NODES)
#define LBK_INVALID_ID		(-1)

#define LBK_NUM_CHANS		64
#define LBK_BASE_CHAN(__lbk)	(0x0 | ((__lbk) << 8)) /* PKI_CHAN_E */

/* LBK CSR offsets (within a single LBK device) */
#define LBK_SFT_RST		0x0
#define LBK_CLK_GATE_CTL	0x8
#define LBK_CONST		0x10
#define LBK_CONST1		0x18
#define LBK_BIST_RESULT		0x20
#define LBK_ERR_INT		0x40
#define LBK_ERR_INT_W1S		0x48
#define LBK_ERR_INT_ENA_W1C	0x50
#define LBK_ERR_INT_ENA_W1S	0x58
#define LBK_ECC_CFG		0x60
#define LBK_CH_PKIND(__ch)	(0x200 | ((__ch) << 3))
#define LBK_MSIX_VEC_ADDR	0xF00000
#define LBK_MSIX_VEC_CTL	0xF00008
#define LBK_MSIX_PBA		0xFF0000

/* LBK device domain connect mode (See LBK_CONNECT_E in HRM) */
#define LBK_CONNECT_E_NIC	0x0
#define LBK_CONNECT_E_PKI	0x4
#define LBK_CONNECT_E_PKO	0x8

/* LBK device Configuration and Control Block */
struct lbkpf {
	struct list_head list; /* List of LBK devices */
	struct pci_dev *pdev;
	void __iomem *reg_base;
	struct msix_entry *msix_entries;
	int id; /* Global/multinode LBK device ID (node + LBK index).*/
	int channels; /* Number of channels in the LBK device. */
	int iconn; /* Ingress connection (LBK_CONNECT_E_nnn). */
	int oconn; /* Egress connection (LBK_CONNECT_E_nnn). */
};

/* Global list of LBK devices and ports. */
static DEFINE_SPINLOCK(octeontx_lbk_lock);
static LIST_HEAD(octeontx_lbk_devices);
static struct octtx_lbk_port octeontx_lbk_ports[LBK_MAX_PORTS] = {
	{.glb_port_idx = 0, .domain_id = LBK_INVALID_ID},
	{.glb_port_idx = 1, .domain_id = LBK_INVALID_ID}
};

/* Interface with Thunder NIC driver */
static struct thunder_lbk_com_s *thlbk;

static int lbk_index_from_id(int id)
{
	return id & LBK_DEV_MASK;
}

static int lbk_node_from_id(int id)
{
	return id >> LBK_NODE_SHIFT;
}

static int lbk_id_from_node_devidx(int node, int lbk)
{
	return (node << LBK_NODE_SHIFT) | lbk;
}

static struct lbkpf *get_lbk_dev(int node, int lbk)
{
	struct lbkpf *dev;
	int id = lbk_id_from_node_devidx(node, lbk);

	list_for_each_entry(dev, &octeontx_lbk_devices, list) {
		if (dev->id == id)
			return dev;
	}
	return NULL;
}

static struct octtx_lbk_port *get_lbk_port(int domain_id, int port_idx)
{
	struct octtx_lbk_port *port;
	int i;

	spin_lock(&octeontx_lbk_lock);
	for (i = 0; i < LBK_MAX_PORTS; i++) {
		port = &octeontx_lbk_ports[i];
		if (port->domain_id == domain_id &&
		    port->dom_port_idx == port_idx) {
			spin_unlock(&octeontx_lbk_lock);
			return port;
		}
	}
	spin_unlock(&octeontx_lbk_lock);
	return NULL;
}

static void lbk_reg_write(struct lbkpf *lbk, u64 offset, u64 val)
{
	writeq_relaxed(val, lbk->reg_base + offset);
}

static u64 lbk_reg_read(struct lbkpf *lbk, u64 offset)
{
	return readq_relaxed(lbk->reg_base + offset);
}

/* LBK Interface functions.
 */
static int lbk_get_num_ports(int node)
{
	return LBK_MAX_PORTS;
}

/* NOTE: This version of the function searches for port by the channel
 * number used by the port's egress part.
 */
static struct octtx_lbk_port *lbk_get_port_by_chan(int node, u16 domain_id,
						   int chan)
{
	struct octtx_lbk_port *port;
	int i, max_chan;

	spin_lock(&octeontx_lbk_lock);
	for (i = 0; i < LBK_MAX_PORTS; i++) {
		port = &octeontx_lbk_ports[i];
		if (port->domain_id == LBK_INVALID_ID ||
		    port->domain_id != domain_id ||
				port->node != node)
			continue;
		max_chan = port->olbk_base_chan + port->olbk_num_chans;
		if (chan >= port->olbk_base_chan && chan < max_chan) {
			spin_unlock(&octeontx_lbk_lock);
			return port;
		}
	}
	spin_unlock(&octeontx_lbk_lock);
	return NULL;
}

/* Main MBOX message processing function.
 */
static int lbk_port_start(struct octtx_lbk_port *port);
static int lbk_port_stop(struct octtx_lbk_port *port);
static int lbk_port_config(struct octtx_lbk_port *port,
			   mbox_lbk_port_conf_t *conf);
static int lbk_port_status(struct octtx_lbk_port *port,
			   mbox_lbk_port_status_t *stat);

static int lbk_receive_message(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req, union mbox_data *resp,
			       void *mdata)
{
	struct octtx_lbk_port *port;
	int rc = 0;

	/* Determine LBK devices, which back this domain:port */
	port = get_lbk_port(domain_id, hdr->vfid);
	if (!port || !mdata) {
		rc = -ENODEV;
		goto err;
	}
	/* Process messages */
	switch (hdr->msg) {
	case MBOX_LBK_PORT_OPEN:
		lbk_port_config(port, mdata);
		resp->data = sizeof(mbox_lbk_port_conf_t);
		break;
	case MBOX_LBK_PORT_CLOSE:
		resp->data = 0;
		break;
	case MBOX_LBK_PORT_GET_CONFIG:
		lbk_port_config(port, mdata);
		resp->data = sizeof(mbox_lbk_port_conf_t);
		break;
	case MBOX_LBK_PORT_GET_STATUS:
		lbk_port_status(port, mdata);
		resp->data = sizeof(mbox_lbk_port_status_t);
		break;
	case MBOX_BGX_PORT_GET_LINK_STATUS:
		*(u8 *)mdata = 1; /* Always up. */
		resp->data = sizeof(u8);
		break;
	case MBOX_LBK_PORT_GET_STATS:
		memset(mdata, 0, sizeof(mbox_lbk_port_stats_t));
		resp->data = sizeof(mbox_lbk_port_stats_t);
		break;
	case MBOX_LBK_PORT_START:
		rc = lbk_port_start(port);
		if (rc < 0) {
			rc = -EIO;
			goto err;
		}
		resp->data = 0;
		break;
	case MBOX_LBK_PORT_STOP:
		lbk_port_stop(port);
		resp->data = 0;
		break;
	case MBOX_LBK_PORT_CLR_STATS:
		resp->data = 0;
		break;

	default:
		hdr->res_code = MBOX_RET_INVALID;
		return -EINVAL;
	}
	hdr->res_code = MBOX_RET_SUCCESS;
	return 0;
err:
	hdr->res_code = MBOX_RET_INVALID;
	return rc;
}

/* MBOX message processing support functions.
 */
int lbk_port_start(struct octtx_lbk_port *port)
{
	int rc, pkind, i;
	struct lbkpf *lbk;

	if (port->glb_port_idx == 1) {
		rc = thlbk->port_start();
		if (rc)
			return -EIO;
		pkind = thlbk->get_port_pkind();
	} else {
		pkind = port->pkind;
	}
	lbk = get_lbk_dev(port->node, port->ilbk);
	for (i = 0; i < lbk->channels; i++)
		lbk_reg_write(lbk, LBK_CH_PKIND(i), port->pkind);
	lbk = get_lbk_dev(port->node, port->olbk);
	for (i = 0; i < lbk->channels; i++)
		lbk_reg_write(lbk, LBK_CH_PKIND(i), pkind);
	return 0;
}

int lbk_port_stop(struct octtx_lbk_port *port)
{
	struct lbkpf *lbk;
	int i;

	if (port->glb_port_idx == 1)
		thlbk->port_stop();
	lbk = get_lbk_dev(port->node, port->ilbk);
	for (i = 0; i < lbk->channels; i++)
		lbk_reg_write(lbk, LBK_CH_PKIND(i), 0);
	lbk = get_lbk_dev(port->node, port->olbk);
	for (i = 0; i < lbk->channels; i++)
		lbk_reg_write(lbk, LBK_CH_PKIND(i), 0);
	return 0;
}

int lbk_port_config(struct octtx_lbk_port *port, mbox_lbk_port_conf_t *conf)
{
	u64 reg;
	struct lbkpf *ilbk = get_lbk_dev(port->node, port->ilbk);
	struct lbkpf *olbk = get_lbk_dev(port->node, port->olbk);

	reg = lbk_reg_read(ilbk, LBK_CH_PKIND(0));
	conf->pkind = reg & ((1ull << 5) - 1);
	conf->ilbk = port->ilbk;
	conf->base_ichan = port->ilbk * ilbk->channels;
	conf->num_ichans = ilbk->channels;
	conf->olbk = port->olbk;
	conf->base_ochan = port->olbk * olbk->channels;
	conf->num_ochans = olbk->channels;
	conf->node = port->node;
	conf->enabled = 1; /* LBK is always enabled.*/
	return 0;
}

int lbk_port_status(struct octtx_lbk_port *port, mbox_lbk_port_status_t *stat)
{
	u64 reg;
	struct lbkpf *ilbk = get_lbk_dev(port->node, port->ilbk);
	struct lbkpf *olbk = get_lbk_dev(port->node, port->olbk);

	reg = lbk_reg_read(ilbk, LBK_ERR_INT);
	stat->chan_oflow = !!(reg & (1ull << 5));
	stat->chan_uflow = !!(reg & (1ull << 4));
	stat->data_oflow = !!(reg & (1ull << 3));
	stat->data_uflow = !!(reg & (1ull << 2));

	reg = lbk_reg_read(olbk, LBK_ERR_INT);
	stat->chan_oflow |= !!(reg & (1ull << 5));
	stat->chan_uflow |= !!(reg & (1ull << 4));
	stat->data_oflow |= !!(reg & (1ull << 3));
	stat->data_uflow |= !!(reg & (1ull << 2));
	/* TODO: Clear interrupts? */

	stat->link_up = 1; /* Link is always up */
	return 0;
}

/* Domain destroy function.
 */
static int lbk_destroy_domain(u32 id, u16 domain_id)
{
	struct octtx_lbk_port *port;
	int i;

	spin_lock(&octeontx_lbk_lock);
	for (i = 0; i < LBK_MAX_PORTS; i++) {
		port = &octeontx_lbk_ports[i];
		if (port->domain_id != domain_id)
			continue;
		port->domain_id = LBK_INVALID_ID;
	}
	spin_unlock(&octeontx_lbk_lock);
	return 0;
}

/* Domain create function.
 */
static int lbk_create_domain(u32 id, u16 domain_id,
			     struct octtx_lbk_port *port_tbl, int port_count,
			     struct octeontx_master_com_t *com, void *domain)
{
	struct octtx_lbk_port *port, *gport;
	int i, j, rc = 0;

	spin_lock(&octeontx_lbk_lock);
	for (i = 0; i < port_count; i++) {
		port = &port_tbl[i];
		for (j = 0; j < LBK_MAX_PORTS; j++) {
			gport = &octeontx_lbk_ports[j];
			if (port->glb_port_idx != gport->glb_port_idx)
				continue;
			/* Check for conflicts with other domains. */
			if (gport->domain_id != LBK_INVALID_ID) {
				rc = -EINVAL;
				goto err;
			}

			port->node = gport->node;
			port->ilbk = gport->ilbk;
			port->olbk = gport->olbk;
			port->ilbk_base_chan = gport->ilbk_base_chan;
			port->ilbk_num_chans = gport->ilbk_num_chans;
			port->olbk_base_chan = gport->olbk_base_chan;
			port->olbk_num_chans = gport->olbk_num_chans;
			gport->pkind = port->pkind;
			gport->domain_id = domain_id;
			gport->dom_port_idx = i;
		}
	}

	spin_unlock(&octeontx_lbk_lock);
	return rc;

err:
	spin_unlock(&octeontx_lbk_lock);
	lbk_destroy_domain(id, domain_id);
	return rc;
}

/* Domain reset function.
 */
static int lbk_reset_domain(u32 id, u16 domain_id)
{
	struct octtx_lbk_port *port;
	int i;

	spin_lock(&octeontx_lbk_lock);
	for (i = 0; i < LBK_MAX_PORTS; i++) {
		port = &octeontx_lbk_ports[i];
		if (port->domain_id != domain_id)
			continue;
		lbk_port_stop(port);
	}
	spin_unlock(&octeontx_lbk_lock);
	return 0;
}

/* Interface with the main OCTEONTX driver.
 */
struct lbk_com_s lbk_com  = {
	.create_domain = lbk_create_domain,
	.destroy_domain = lbk_destroy_domain,
	.reset_domain = lbk_reset_domain,
	.receive_message = lbk_receive_message,
	.get_num_ports = lbk_get_num_ports,
	.get_port_by_chan = lbk_get_port_by_chan
};
EXPORT_SYMBOL(lbk_com);

/* Driver startup initialization and shutdown functions.
 */
static int lbk_init(struct lbkpf *lbk)
{
	u64 reg;

	reg = lbk_reg_read(lbk, LBK_CONST);
	lbk->channels = (reg >> 32) & 0xFFFF;
	lbk->iconn = (reg >> 28) & 0xF;
	lbk->oconn = (reg >> 24) & 0xF;
	return 0;
}

static int lbk_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct octtx_lbk_port *port = NULL;
	struct lbkpf *lbk;
	u64 ioaddr;
	int err, node;

	/* Setup LBK Device */
	lbk = devm_kzalloc(dev, sizeof(*lbk), GFP_KERNEL);
	if (!lbk)
		return -ENOMEM;

	pci_set_drvdata(pdev, lbk);
	lbk->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		return err;
	}
	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed\n");
		return err;
	}
	lbk->reg_base = pcim_iomap(pdev, PCI_LBK_CFG_BAR, 0);
	if (!lbk->reg_base) {
		dev_err(dev, "Can't map CFG space\n");
		return -ENOMEM;
	}
	ioaddr = pci_resource_start(pdev, PCI_LBK_CFG_BAR);
	node = (ioaddr >> 44) & 0x3;
	lbk->id = ((node * LBK_DEV_PER_CPU) << LBK_NODE_SHIFT) |
		((ioaddr >> 24) & 0x3);

	if (lbk_init(lbk) < 0) {
		dev_err(dev, "Failed to initialize LBK device.\n");
		return -EIO;
	}
	INIT_LIST_HEAD(&lbk->list);
	list_add(&lbk->list, &octeontx_lbk_devices);

	/* Setup LBK Port */
	if (lbk->iconn == LBK_CONNECT_E_PKI &&
	    lbk->oconn == LBK_CONNECT_E_PKO) {
		port = &octeontx_lbk_ports[0];
		port->ilbk = lbk_index_from_id(lbk->id);
		port->olbk = lbk_index_from_id(lbk->id);
		port->ilbk_base_chan = LBK_BASE_CHAN(port->ilbk);
		port->ilbk_num_chans = LBK_NUM_CHANS;
		port->olbk_base_chan = LBK_BASE_CHAN(port->olbk);
		port->olbk_num_chans = LBK_NUM_CHANS;
	} else if (lbk->iconn == LBK_CONNECT_E_PKI &&
			lbk->oconn == LBK_CONNECT_E_NIC) {
		port = &octeontx_lbk_ports[1];
		port->ilbk = lbk_index_from_id(lbk->id);
		port->ilbk_base_chan = LBK_BASE_CHAN(port->ilbk);
		port->ilbk_num_chans = LBK_NUM_CHANS;
	} else if (lbk->iconn == LBK_CONNECT_E_NIC &&
			lbk->oconn == LBK_CONNECT_E_PKO) {
		port = &octeontx_lbk_ports[1];
		port->olbk = lbk_index_from_id(lbk->id);
		port->olbk_base_chan = LBK_BASE_CHAN(port->olbk);
		port->olbk_num_chans = LBK_NUM_CHANS;
	} else {
		/* LBK:NIC-to-NIC is not used.*/
		return 0;
	}
	INIT_LIST_HEAD(&port->list);
	port->node = lbk_node_from_id(lbk->id);
	return 0;
}

static void lbk_remove(struct pci_dev *pdev)
{
	struct lbkpf *lbk = pci_get_drvdata(pdev);
	struct lbkpf *curr;

	if (!lbk)
		return;

	spin_lock(&octeontx_lbk_lock);
	list_for_each_entry(curr, &octeontx_lbk_devices, list) {
		if (curr == lbk) {
			list_del(&lbk->list);
			break;
		}
	}
	spin_unlock(&octeontx_lbk_lock);
}

static const struct pci_device_id lbk_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_LBK) },
	{ 0 } /* End of table */
};

static struct pci_driver lbk_driver = {
	.name = DRV_NAME,
	.id_table = lbk_id_table,
	.probe = lbk_probe,
	.remove = lbk_remove,
};

MODULE_AUTHOR("Cavium");
MODULE_DESCRIPTION("Cavium OCTEONTX LBK Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, lbk_id_table);

static int __init lbk_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);
	thlbk = try_then_request_module(symbol_get(thunder_lbk_com), "nicpf");
	if (!thlbk)
		return -ENODEV;

	return pci_register_driver(&lbk_driver);
}

static void __exit lbk_cleanup_module(void)
{
	pci_unregister_driver(&lbk_driver);
	symbol_put(thunder_lbk_com);
}

module_init(lbk_init_module);
module_exit(lbk_cleanup_module);

