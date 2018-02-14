/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/random.h>

#include "sli.h"

#define SLI_DRV_NAME    "octeontx-sli"
#define SLI_DRV_VERSION "0.1"

#define PKI_CHAN_E_SDP_CHX(a) (0x400 + (a))

#define PKO_LMAC_E_SDP   2

static atomic_t sli_count = ATOMIC_INIT(0);

#define SDP_INVALID_ID  (-1)

/* Global lists of SDP devices and ports */
static DEFINE_MUTEX(octeontx_sli_devices_lock);
static DEFINE_MUTEX(octeontx_sdp_lock);
static LIST_HEAD(octeontx_sli_devices);
static LIST_HEAD(octeontx_sdp_ports);

/* Register read/write APIs */
static void sli_reg_write(struct slipf *sli, u64 offset, u64 val)
{
	writeq_relaxed(val, sli->reg_base + offset);
}

static u64 sli_reg_read(struct slipf *sli, u64 offset)
{
	return readq_relaxed(sli->reg_base + offset);
}

static struct slipf *get_sli_dev(int node, int sli_idx)
{
	struct slipf *sli_dev = NULL;

	mutex_lock(&octeontx_sli_devices_lock);
	list_for_each_entry(sli_dev, &octeontx_sli_devices, list) {
		if ((sli_dev) && (sli_dev->node == node) &&
		    (sli_dev->sli_idx == sli_idx))
			break;
	}
	mutex_unlock(&octeontx_sli_devices_lock);
	return sli_dev;
}

static struct octtx_sdp_port *get_sdp_port(int domain_id,
					   int port_idx __maybe_unused)
{
	struct octtx_sdp_port *sdp_port = NULL;

	mutex_lock(&octeontx_sdp_lock);
	list_for_each_entry(sdp_port, &octeontx_sdp_ports, list) {
		if ((sdp_port) && (sdp_port->domain_id == domain_id))
			break;
	}
	mutex_unlock(&octeontx_sdp_lock);
	return sdp_port;
}

/* SLI Interface functions. */
static int sli_get_num_ports(int node)
{
	struct octtx_sdp_port *sdp_port = NULL;
	int count = 0;

	mutex_lock(&octeontx_sdp_lock);
	list_for_each_entry(sdp_port, &octeontx_sdp_ports, list) {
		if ((sdp_port) && (sdp_port->node == node))
			count++;
	}
	mutex_unlock(&octeontx_sdp_lock);
	return count;
}

static bool sli_get_link_status(int node __maybe_unused,
				int sdp __maybe_unused,
				int lmac __maybe_unused)
{
	return true;
}

/* Main MBOX message processing function.  */
static int sdp_port_open(struct octtx_sdp_port *port);
static int sdp_port_close(struct octtx_sdp_port *port);
static int sdp_port_start(struct octtx_sdp_port *port);
static int sdp_port_stop(struct octtx_sdp_port *port);
static int sdp_port_config(struct octtx_sdp_port *port,
			   struct mbox_sdp_port_conf *conf);
static int sdp_port_status(struct octtx_sdp_port *port,
			   struct mbox_sdp_port_status *stat);
static int sdp_port_stats_get(struct octtx_sdp_port *port,
			      struct mbox_sdp_port_stats *stat);
static int sdp_port_stats_clr(struct octtx_sdp_port *port);
static int sdp_port_link_status(struct octtx_sdp_port *port, u8 *up);
static void sdp_reg_read(struct mbox_sdp_reg *reg);
static void sdp_reg_write(struct mbox_sdp_reg *reg);

static int sli_receive_message(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp, void *mdata)
{
	struct octtx_sdp_port *sdp_port = NULL;

	if (!mdata)
		return -ENOMEM;

	sdp_port = get_sdp_port(domain_id, hdr->vfid);
	if (!sdp_port) {
		hdr->res_code = MBOX_RET_INVALID;
		return -ENODEV;
	}

	switch (hdr->msg) {
	case MBOX_SDP_PORT_OPEN:
		sdp_port_open(sdp_port);
		sdp_port_config(sdp_port, mdata);
		resp->data = sizeof(struct mbox_sdp_port_conf);
		break;

	case MBOX_SDP_PORT_CLOSE:
		sdp_port_close(sdp_port);
		resp->data = 0;
		break;

	case MBOX_SDP_PORT_START:
		sdp_port_start(sdp_port);
		resp->data = 0;
		break;

	case MBOX_SDP_PORT_STOP:
		sdp_port_stop(sdp_port);
		resp->data = 0;
		break;

	case MBOX_SDP_PORT_GET_CONFIG:
		sdp_port_config(sdp_port, mdata);
		resp->data = sizeof(struct mbox_sdp_port_conf);
		break;

	case MBOX_SDP_PORT_GET_STATUS:
		sdp_port_status(sdp_port, mdata);
		resp->data = sizeof(struct mbox_sdp_port_status);
		break;

	case MBOX_SDP_PORT_GET_STATS:
		sdp_port_stats_get(sdp_port, mdata);
		resp->data = sizeof(struct mbox_sdp_port_stats);
		break;

	case MBOX_SDP_PORT_CLR_STATS:
		sdp_port_stats_clr(sdp_port);
		resp->data = 0;
		break;

	case MBOX_SDP_PORT_GET_LINK_STATUS:
		sdp_port_link_status(sdp_port, mdata);
		resp->data = sizeof(u8);
		break;

	case MBOX_SDP_REG_READ:
		sdp_reg_read(mdata);
		resp->data = sizeof(struct mbox_sdp_reg);
		break;

	case MBOX_SDP_REG_WRITE:
		sdp_reg_write(mdata);
		resp->data = 0;
		break;

	default:
		hdr->res_code = MBOX_RET_INVALID;
		return -EINVAL;
	}

	hdr->res_code = MBOX_RET_SUCCESS;
	return 0;
}

/* MBOX message processing support functions. */
int sdp_port_open(struct octtx_sdp_port *port __maybe_unused)
{
	return 0;
}

int sdp_port_close(struct octtx_sdp_port *port __maybe_unused)
{
	return 0;
}

int sdp_port_start(struct octtx_sdp_port *port __maybe_unused)
{
	return 0;
}

int sdp_port_stop(struct octtx_sdp_port *port __maybe_unused)
{
	return 0;
}

int sdp_port_config(struct octtx_sdp_port *sdp_port,
		    struct mbox_sdp_port_conf *conf)
{
	conf->node  = sdp_port->node;
	conf->sdp   = sdp_port->sdp;
	conf->lmac  = sdp_port->lmac;
	conf->base_chan = sdp_port->base_chan;
	conf->num_chans = sdp_port->num_chans;

	return 0;
}

int sdp_port_status(struct octtx_sdp_port *port __maybe_unused,
		    struct mbox_sdp_port_status *stat __maybe_unused)
{
	return 0;
}

int sdp_port_stats_get(struct octtx_sdp_port *port __maybe_unused,
		       struct mbox_sdp_port_stats *stats __maybe_unused)
{
	return 0;
}

int sdp_port_stats_clr(struct octtx_sdp_port *port __maybe_unused)
{
	return 0;
}

int sdp_port_link_status(struct octtx_sdp_port *port __maybe_unused,
			 u8 *up __maybe_unused)
{
	return 0;
}

void sdp_reg_read(struct mbox_sdp_reg *reg)
{
	struct slipf *sli = get_sli_dev(0, 0); /* Hard coding for now */

	reg->val = sli_reg_read(sli, reg->addr);
}

void sdp_reg_write(struct mbox_sdp_reg *reg)
{
	struct slipf *sli = get_sli_dev(0, 0); /* Hard coding for now */

	sli_reg_write(sli, reg->addr, reg->val);
}

/* Domain create function.  */
static int sli_create_domain(u32 id, u16 domain_id,
			     struct octtx_sdp_port *port_tbl, int ports,
			     struct octeontx_master_com_t *com, void *domain,
			     struct kobject *kobj __maybe_unused)
{
	struct octtx_sdp_port *sdp_port = NULL, *gport = NULL;
	struct slipf *sli  = NULL;
	struct slipf *curr = NULL;
	int port_idx;

	/* TODO: Add sysfs entries */

	mutex_lock(&octeontx_sli_devices_lock);
	list_for_each_entry(curr, &octeontx_sli_devices, list) {
		if (curr->id == id) {
			sli = curr;
			break;
		}
	}
	mutex_unlock(&octeontx_sli_devices_lock);

	if (!sli)
		return -ENODEV;

	/* For each domain port, find requested entry in the list of
	 * global ports and sync up those two port structures.
	 */
	mutex_lock(&octeontx_sdp_lock);
	for (port_idx = 0; port_idx < ports; port_idx++) {
		sdp_port = &port_tbl[port_idx];

		list_for_each_entry(gport, &octeontx_sdp_ports, list) {
			if ((gport->node != id) ||
			    (gport->glb_port_idx != sdp_port->glb_port_idx))
				continue;
			/* Check for conflicts with other domains. */
			if (gport->domain_id != SDP_INVALID_ID) {
				mutex_unlock(&octeontx_sdp_lock);
				return -EINVAL;
			}

			/* TODO: Add sysfs entries */
			/* Domain port: */
			sdp_port->node = gport->node;
			sdp_port->lmac = gport->lmac;
			sdp_port->lmac_type = gport->lmac_type;
			sdp_port->base_chan = gport->base_chan;
			sdp_port->num_chans = gport->num_chans;

			/* Global port: */
			gport->domain_id = domain_id;
			gport->dom_port_idx = port_idx;
		}
	}
	mutex_unlock(&octeontx_sdp_lock);
	dev_info(&sli->pdev->dev, "sli domain creation is successful\n");

	return 0;
}

/* Domain destroy function.  */
static int sli_destroy_domain(u32 id, u16 domain_id,
			      struct kobject *kobj __maybe_unused)
{
	struct octtx_sdp_port *sdp_port = NULL;

	/* TODO: Add sysfs entries */

	mutex_lock(&octeontx_sdp_lock);
	list_for_each_entry(sdp_port, &octeontx_sdp_ports, list) {
		if ((sdp_port) && (sdp_port->node == id) &&
		    (sdp_port->domain_id == domain_id)) {
			sdp_port->domain_id = SDP_INVALID_ID;
			sdp_port->dom_port_idx = SDP_INVALID_ID;
		}
	}
	mutex_unlock(&octeontx_sdp_lock);

	return 0;
}

/* Domain reset function. */
static int sli_reset_domain(u32 id, u16 domain_id)
{
	struct octtx_sdp_port *sdp_port = NULL;

	mutex_lock(&octeontx_sdp_lock);
	list_for_each_entry(sdp_port, &octeontx_sdp_ports, list) {
		if ((sdp_port) && (sdp_port->node == id) &&
		    (sdp_port->domain_id == domain_id))
			sdp_port_stop(sdp_port);
	}
	mutex_unlock(&octeontx_sdp_lock);

	return 0;
}

/* Set pkind for a given port. */
static int sli_set_pkind(u32 id, u16 domain_id, int port, int pkind)
{
	struct octtx_sdp_port *gport = NULL;

	gport = get_sdp_port(domain_id, port);
	if (!gport)
		return -ENODEV;

	/* Domain port: */
	gport->pkind = pkind;

	return 0;
}

static int sli_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct octtx_sdp_port *sdp_port = NULL;
	struct slipf *sli = NULL;

	int port_idx;
	int port_count = 0;
	int node = 0;
	int err = 0;
	struct list_head *pos, *tmppos;

	sli = devm_kzalloc(dev, sizeof(*sli), GFP_KERNEL);
	if (!sli)
		return -ENOMEM;

	pci_set_drvdata(pdev, sli);
	sli->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto err_free_device;
	}

	err = pci_request_regions(pdev, SLI_DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed\n");
		goto err_disable_device;
	}

	/* Map BAR space CFG registers */
	sli->reg_base = pcim_iomap(pdev, PCI_SLI_PF_CFG_BAR, 0);
	if (!sli->reg_base) {
		dev_err(dev, "Can't map CFG space\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	/*set SLI ID */
	sli->id = atomic_add_return(1, &sli_count);
	sli->id -= 1;

	sli->port_count = 1;
	sli->node = node;
	sli->sli_idx = 0;
	INIT_LIST_HEAD(&sli->list);

	for (port_idx = 0; port_idx < sli->port_count; port_idx++) {
		sdp_port = kzalloc(sizeof(*sdp_port), GFP_KERNEL);
		if (!sdp_port) {
			err = -ENOMEM;
			goto err_free_sdp_ports;
		}

		sdp_port->glb_port_idx = port_idx;
		sdp_port->sdp = port_idx;
		sdp_port->node = node;
		sdp_port->lmac = PKO_LMAC_E_SDP;
		sdp_port->base_chan = PKI_CHAN_E_SDP_CHX(port_idx);
		sdp_port->num_chans = 8;
		sdp_port->domain_id = SDP_INVALID_ID;
		sdp_port->dom_port_idx = SDP_INVALID_ID;

		INIT_LIST_HEAD(&sdp_port->list);
		mutex_lock(&octeontx_sdp_lock);
		list_add(&sdp_port->list, &octeontx_sdp_ports);
		mutex_unlock(&octeontx_sdp_lock);

		port_count++;
		sdp_port = NULL;
	}

	mutex_lock(&octeontx_sli_devices_lock);
	list_add(&sli->list, &octeontx_sli_devices);
	mutex_unlock(&octeontx_sli_devices_lock);

	return 0;

err_free_sdp_ports:
	mutex_lock(&octeontx_sdp_lock);
	list_for_each_safe(pos, tmppos, &octeontx_sdp_ports) {
		port_idx--;
		sdp_port = list_entry(pos, struct octtx_sdp_port, list);
		if ((sdp_port) && (sdp_port->sdp == port_idx)) {
			list_del(pos);
			kfree(sdp_port);
		}
	}
	mutex_unlock(&octeontx_sdp_lock);

err_release_regions:
	if (sli->reg_base)
		iounmap(sli->reg_base);
	pci_release_regions(pdev);

err_disable_device:
	pci_disable_device(pdev);

err_free_device:
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, sli);

	return err;
}

static void sli_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct slipf *sli = pci_get_drvdata(pdev);
	struct slipf *curr = NULL;
	struct octtx_sdp_port *sdp_port = NULL;
	struct list_head *pos, *tmppos;

	if (!sli)
		return;

	/* First of all, this SLI device's SDP port list and its memory has
	 * to be freed.
	 */
	mutex_lock(&octeontx_sdp_lock);
	list_for_each_safe(pos, tmppos, &octeontx_sdp_ports) {
		sdp_port = list_entry(pos, struct octtx_sdp_port, list);
		if (sdp_port) {
			list_del(pos);
			kfree(sdp_port);
		}
	}
	mutex_unlock(&octeontx_sdp_lock);

	mutex_lock(&octeontx_sli_devices_lock);
	list_for_each_entry(curr, &octeontx_sli_devices, list) {
		if (curr == sli) {
			list_del(&sli->list);
			break;
		}
	}
	mutex_unlock(&octeontx_sli_devices_lock);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, sli);
}

/* Interface with the main OCTEONTX driver. */
struct slipf_com_s slipf_com  = {
	.create_domain   = sli_create_domain,
	.destroy_domain     = sli_destroy_domain,
	.reset_domain    = sli_reset_domain,
	.receive_message = sli_receive_message,
	.get_num_ports   = sli_get_num_ports,
	.get_link_status = sli_get_link_status,
	.set_pkind       = sli_set_pkind
};
EXPORT_SYMBOL(slipf_com);

/* devices supported */
static const struct pci_device_id sli_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_SLI_PF) },
	{ 0, } /* end of table */
};

static struct pci_driver sli_driver = {
	.name     = SLI_DRV_NAME,
	.id_table = sli_id_table,
	.probe    = sli_probe,
	.remove   = sli_remove,
};

MODULE_AUTHOR("Cavium");
MODULE_DESCRIPTION("Cavium OCTEONTX SLI Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(SLI_DRV_VERSION);
MODULE_DEVICE_TABLE(pci, sli_id_table);

static int __init sli_init_module(void)
{
	pr_info("%s, ver %s\n", SLI_DRV_NAME, SLI_DRV_VERSION);

	return pci_register_driver(&sli_driver);
}

static void __exit sli_cleanup_module(void)
{
	pci_unregister_driver(&sli_driver);
}

module_init(sli_init_module);
module_exit(sli_cleanup_module);
