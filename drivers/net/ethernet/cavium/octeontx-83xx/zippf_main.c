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
#include <linux/of.h>

#include "zip.h"

#define DRV_NAME "octeontx-zip"
#define DRV_VERSION "1.0"

static atomic_t zip_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(octeontx_zip_devices_lock);
static LIST_HEAD(octeontx_zip_devices);
static DEFINE_MUTEX(pf_mbox_lock);

/* ZIP register write API */
static void zip_reg_write(struct zippf *zip, u64 offset, u64 val)
{
	writeq_relaxed(val, zip->reg_base + offset);
}

/* ZIP register read API */
static u64 zip_reg_read(struct zippf *zip, u64 offset)
{
	return readq_relaxed(zip->reg_base + offset);
}

static void identify(struct zippf_vf *vf, u16 domain_id, u16 subdomain_id)
{
	/* sub_domainid | domainid */
	u64 reg = ((subdomain_id << 16) | domain_id);

	writeq_relaxed(reg, vf->domain.reg_base + ZIP_VF_PF_MBOXX(0));
}

static int zip_pf_destroy_domain(u32 id, u16 domain_id, struct kobject *kobj)
{
	struct zippf *zip = NULL;
	struct zippf *curr;
	u64 reg;
	int i, vf_idx = 0;
	struct pci_dev *virtfn;

	mutex_lock(&octeontx_zip_devices_lock);
	list_for_each_entry(curr, &octeontx_zip_devices, list) {
		if (curr->id == id) {
			zip = curr;
			break;
		}
	}

	if (!zip) {
		mutex_unlock(&octeontx_zip_devices_lock);
		return -ENODEV;
	}

	for (i = 0; i < zip->total_vfs; i++) {
		if (zip->vf[i].domain.in_use &&
		    zip->vf[i].domain.domain_id == domain_id) {
			zip->vf[i].domain.in_use = false;
			identify(&zip->vf[i], 0x0, 0x0);
			reg = zip_reg_read(zip, ZIP_PF_QUEX_GMCTL(i));
			reg &= ~0xFFFFull; /*GMID*/
			zip_reg_write(zip, ZIP_PF_QUEX_GMCTL(i), reg);

			if (zip->vf[i].domain.reg_base)
				iounmap(zip->vf[i].domain.reg_base);

			virtfn = pci_get_domain_bus_and_slot(
					pci_domain_nr(zip->pdev->bus),
					pci_iov_virtfn_bus(zip->pdev, i),
					pci_iov_virtfn_devfn(zip->pdev, i));

			if (virtfn && kobj)
				sysfs_remove_link(kobj, virtfn->dev.kobj.name);

			dev_info(&zip->pdev->dev,
				 "Free vf[%d] from domain:%d subdomain_id:%d\n",
				 i, zip->vf[i].domain.domain_id, vf_idx);
			vf_idx++;
		}
	}

	zip->vfs_in_use -= vf_idx;
	mutex_unlock(&octeontx_zip_devices_lock);
	return 0;
}

static int zip_pf_create_domain(u32 id, u16 domain_id, u32 num_vfs,
				void *master, void *master_data,
				struct kobject *kobj)
{
	struct zippf *zip = NULL;
	struct zippf *curr;
	resource_size_t vf_start;
	u64 reg;
	int i, vf_idx = 0, ret = 0;
	struct pci_dev *virtfn;

	union zip_quex_sbuf_ctl		quex_sbuf_ctl;
	union zip_quex_map		quex_map;

	if (!kobj)
		return -EINVAL;

	mutex_lock(&octeontx_zip_devices_lock);
	list_for_each_entry(curr, &octeontx_zip_devices, list) {
		if (curr->id == id) {
			zip = curr;
			break;
		}
	}

	if (!zip) {
		ret = -ENODEV;
		goto err_unlock;
	}

	for (i = 0; i < zip->total_vfs; i++) {
		if (zip->vf[i].domain.in_use) {
			continue;
		} else {
			virtfn = pci_get_domain_bus_and_slot(
					pci_domain_nr(zip->pdev->bus),
					pci_iov_virtfn_bus(zip->pdev, i),
					pci_iov_virtfn_devfn(zip->pdev, i));
			if (!virtfn)
				break;

			ret = sysfs_create_link(kobj, &virtfn->dev.kobj,
						virtfn->dev.kobj.name);
			if (ret < 0)
				goto err_unlock;

			zip->vf[i].domain.domain_id = domain_id;
			zip->vf[i].domain.subdomain_id = vf_idx;
			zip->vf[i].domain.gmid = get_gmid(domain_id);

			zip->vf[i].domain.in_use = true;
			zip->vf[i].domain.master = master;
			zip->vf[i].domain.master_data = master_data;

			vf_start = pci_resource_start(zip->pdev,
						      PCI_ZIP_PF_CFG_BAR);
			vf_start += ZIP_VF_OFFSET(i);

			zip->vf[i].domain.reg_base = ioremap(vf_start,
							     ZIP_VF_CFG_SIZE);
			if (!zip->vf[i].domain.reg_base)
				break;

			identify(&zip->vf[i], domain_id, vf_idx);

			/* Program SBUF_CTL of all queues */
			quex_sbuf_ctl.u = 0ull;
			quex_sbuf_ctl.s.inst_be = 0;
			/* for VFs support on Guest */
			quex_sbuf_ctl.s.stream_id = (i + 1);
			quex_sbuf_ctl.s.inst_free = 0;
			zip_reg_write(zip, ZIP_PF_QUEX_SBUF_CTL(i),
				      quex_sbuf_ctl.u);
			dev_info(&zip->pdev->dev,
				 "QUEX_SBUF_CTL[%d]: 0x%016llx\n", i,
				 zip_reg_read(zip, ZIP_PF_QUEX_SBUF_CTL(i)));

			/* Queue-to-ZIP core mapping
			 * If a queue is not mapped to a particular core,
			 * it is equivalent to the ZIP core being disabled.
			 */
			quex_map.u = 0ull;
			/* Map queue to all zip engines */
			quex_map.s.zce = 0x3F;
			zip_reg_write(zip, ZIP_PF_QUEX_MAP(i), quex_map.u);
			dev_info(&zip->pdev->dev, "QUEX_MAP[%d]: 0x%016llx\n",
				 i, zip_reg_read(zip, ZIP_PF_QUEX_MAP(i)));

			/* Program GMID */
			reg = zip->vf[i].domain.gmid;
			zip_reg_write(zip, ZIP_PF_QUEX_GMCTL(i), reg);

			dev_dbg(&zip->pdev->dev, "DOMAIN Details of ZIP\n");

			dev_dbg(&zip->pdev->dev,
				"domain creation @index: %d for domain: %d",
				i, zip->vf[i].domain.domain_id);
			dev_dbg(&zip->pdev->dev,
				"sub domain: %d, gmid: %d, vf_idx: %d\n",
				zip->vf[i].domain.subdomain_id,
				zip->vf[i].domain.gmid, vf_idx);

			vf_idx++;
			if (vf_idx == num_vfs) {
				zip->vfs_in_use += num_vfs;
				break;
			}
		}
	}

	mutex_unlock(&octeontx_zip_devices_lock);
	if (vf_idx != num_vfs) {
		ret = -ENODEV;
		zip_pf_destroy_domain(id, domain_id, kobj);
	}
	return ret;

err_unlock:
	mutex_unlock(&octeontx_zip_devices_lock);
	return ret;
}

static void zip_vfx_reset(struct zippf *zip, int vf)
{
	/* clear domain resources.*/
	zip->vf[vf].domain.in_use = 0;
	zip->vf[vf].domain.master = NULL;
	zip->vf[vf].domain.master_data = NULL;
}

static int zip_pf_reset_domain(u32 id, u16 domain_id)
{
	struct zippf *zip = NULL;
	struct zippf *curr;
	int i;

	mutex_lock(&octeontx_zip_devices_lock);
	list_for_each_entry(curr, &octeontx_zip_devices, list) {
		if (curr->id == id) {
			zip = curr;
			break;
		}
	}

	if (!zip) {
		mutex_unlock(&octeontx_zip_devices_lock);
		return -ENODEV;
	}

	for (i = 0; i < zip->total_vfs; i++) {
		if (zip->vf[i].domain.in_use &&
		    zip->vf[i].domain.domain_id == domain_id) {
			zip_vfx_reset(zip, i);
			identify(&zip->vf[i], domain_id,
				 zip->vf[i].domain.subdomain_id);
		}
	}
	mutex_unlock(&octeontx_zip_devices_lock);
	return 0;
}

static int zip_pf_receive_message(u32 id, u16 domain_id,
				  struct mbox_hdr *hdr, union mbox_data *req,
				  union mbox_data *resp, void *mdata)
{
	return 0;
}

static int zip_pf_get_vf_count(u32 id)
{
	struct zippf *zip = NULL;
	struct zippf *curr;
	int ret = 0;

	mutex_lock(&octeontx_zip_devices_lock);
	list_for_each_entry(curr, &octeontx_zip_devices, list) {
		if (curr->id == id) {
			zip = curr;
			break;
		}
	}

	mutex_unlock(&octeontx_zip_devices_lock);
	if (zip)
		ret = zip->total_vfs;

	return ret;
}

struct zippf_com_s zippf_com = {
	.create_domain = zip_pf_create_domain,
	.destroy_domain = zip_pf_destroy_domain,
	.reset_domain = zip_pf_reset_domain,
	.receive_message = zip_pf_receive_message,
	.get_vf_count = zip_pf_get_vf_count,
};
EXPORT_SYMBOL(zippf_com);

static int zip_sriov_conf(struct pci_dev *pdev, int numvfs)
{
	struct zippf *zip = pci_get_drvdata(pdev);
	int ret = -EBUSY;
	int disable = 0;

	if (zip->vfs_in_use != 0)
		return ret;

	ret = 0;
	if (zip->flags & ZIP_PF_SRIOV_ENABLED)
		disable = 1;

	if (disable) {
		pci_disable_sriov(pdev);
		zip->flags &= ~ZIP_PF_SRIOV_ENABLED;
		zip->total_vfs = 0;
	}

	if (numvfs > 0) {
		ret = pci_enable_sriov(pdev, numvfs);
		if (ret == 0) {
			zip->flags |= ZIP_PF_SRIOV_ENABLED;
			zip->total_vfs = numvfs;
			ret = numvfs;
		}
	}
	dev_notice(&zip->pdev->dev, "ZIP VF's enabled: %d\n", ret);

	return ret;
}

static void zip_init(struct zippf *zip)
{
	/* Initialize zip hardware to defaults */
	union zip_cmd_ctl  cmd_ctl = {0};
	union zip_quex_map quex_map;
	int i;

	/* Enable the ZIP Engine(Core) Clock */
	cmd_ctl.u = zip_reg_read(zip, ZIP_PF_CMD_CTL);
	cmd_ctl.s.forceclk = 1;
	zip_reg_write(zip, ZIP_PF_CMD_CTL, cmd_ctl.u & 0xFF);

	/* Clear queue mapping bits */
	quex_map.u = 0ull;

	/* Initialize domain resources.*/
	for (i = 0; i < ZIP_MAX_VF; i++) {
		zip->vf[i].domain.in_use = 0;
		zip->vf[i].domain.master = NULL;
		zip->vf[i].domain.master_data = NULL;
		/* Unmap queue from all zip engines. */
		zip_reg_write(zip, ZIP_PF_QUEX_MAP(i), quex_map.u);
	}
}

static irqreturn_t zip_pf_ecce_intr_handler (int irq, void *zip_irq)
{
	struct zippf *zip = (struct zippf *)zip_irq;
	u64 zip_reg;

	zip_reg = zip_reg_read(zip, ZIP_PF_ECCE_INT);

	/* clear all interrupts*/
	zip_reg = ~0ull;
	zip_reg_write(zip, ZIP_PF_ECCE_INT, zip_reg);

	return IRQ_HANDLED;
}

static irqreturn_t zip_pf_fife_intr_handler (int irq, void *zip_irq)
{
	struct zippf *zip = (struct zippf *)zip_irq;
	u64 zip_reg;

	zip_reg = zip_reg_read(zip, ZIP_PF_FIFE_INT);

	/* clear all interrupts*/
	zip_reg = ~0ull;
	zip_reg_write(zip, ZIP_PF_FIFE_INT, zip_reg);

	return IRQ_HANDLED;
}

static irqreturn_t zip_pf_mbox_intr_handler (int irq, void *zip_irq)
{
	struct zippf *zip = (struct zippf *)zip_irq;
	u64 reg_val, cmd = 0ull, data = 0ull;
	union zip_quex_sbuf_ctl  quex_sbuf_ctl = {0};
	int i;

	reg_val = zip_reg_read(zip, ZIP_PF_MBOX_INT);
	/* Determine which VF used Mbox service */
	for (i = 0; i < zip->vfs_in_use; i++) {
		if (reg_val & (1ull << i)) {
			/* Read Mbox registers */
			wmb();
			cmd = zip_reg_read(zip,
					   ZIP_PF_VFX_MBOXX(i,
							    ZIP_MBOX0_INDEX));
			data = zip_reg_read(zip,
					    ZIP_PF_VFX_MBOXX(i,
							     ZIP_MBOX1_INDEX));
			if (cmd == ZIP_MBOX_SET_CMD_BUF_SIZE) {
				quex_sbuf_ctl.u = zip_reg_read
					(zip, ZIP_PF_QUEX_SBUF_CTL(i));
				quex_sbuf_ctl.s.size = data;
				zip_reg_write(zip, ZIP_PF_QUEX_SBUF_CTL(i),
					      quex_sbuf_ctl.u);

				zip_reg_write(zip,
					      ZIP_PF_VFX_MBOXX(i,
							       ZIP_MBOX0_INDEX),
					      0ull);
				zip_reg_write(zip,
					      ZIP_PF_VFX_MBOXX(i,
							       ZIP_MBOX1_INDEX),
					      0ull);
				/* Memory barrier */
				wmb();
			}
		}
	}
	/* clear triggered interrupts*/
	zip_reg_write(zip, ZIP_PF_MBOX_INT, reg_val);

	return IRQ_HANDLED;
}

static void zip_irq_free(struct zippf *zip)
{
	int i;
	u64 reg_val;

	/* Clear all enables */
	reg_val = ~0ull;
	zip_reg_write(zip, ZIP_PF_ECCE_ENA_W1C, reg_val);
	zip_reg_write(zip, ZIP_PF_FIFE_ENA_W1C, reg_val);
	zip_reg_write(zip, ZIP_PF_MBOX_ENA_W1C, reg_val);

	for (i = 0; i < ZIP_PF_MSIX_COUNT; i++)
		if (zip->msix_entries[i].vector)
			free_irq(zip->msix_entries[i].vector, zip);

	pci_disable_msix(zip->pdev);
}

static int zip_irq_init(struct zippf *zip)
{
	int ret = 0;
	u64 zip_reg;
	int i;

	/* clear all interrupts */
	zip_reg = ~0ull;
	zip_reg_write(zip, ZIP_PF_ECCE_INT, zip_reg);
	zip_reg_write(zip, ZIP_PF_FIFE_INT, zip_reg);
	zip_reg_write(zip, ZIP_PF_MBOX_INT, zip_reg);

	/* clear all enables */
	zip_reg = ~0ull;
	zip_reg_write(zip, ZIP_PF_ECCE_ENA_W1C, zip_reg);
	zip_reg_write(zip, ZIP_PF_FIFE_ENA_W1C, zip_reg);
	zip_reg_write(zip, ZIP_PF_MBOX_ENA_W1C, zip_reg);

	zip->msix_entries = devm_kzalloc(&zip->pdev->dev,
			ZIP_PF_MSIX_COUNT *
			sizeof(struct msix_entry), GFP_KERNEL);
	if (!zip->msix_entries)
		return -ENOMEM;
	for (i = 0; i < ZIP_PF_MSIX_COUNT; i++)
		zip->msix_entries[i].entry = i;

	ret = pci_enable_msix_exact(zip->pdev, zip->msix_entries, ZIP_PF_MSIX_COUNT);
	if (ret) {
		dev_err(&zip->pdev->dev, "Enabling msix failed(%d)\n", ret);
		return ret;
	}

	/* register ECCE intr handler */
	ret = request_irq(zip->msix_entries[0].vector,
			  zip_pf_ecce_intr_handler, 0, "zippf ecce", zip);
	if (ret)
		goto free_irq;

	/* register FIFE intr handler */
	ret = request_irq(zip->msix_entries[1].vector,
			  zip_pf_fife_intr_handler, 0, "zippf fife", zip);
	if (ret)
		goto free_irq;

	/* register MBOX intr handler */
	ret = request_irq(zip->msix_entries[2].vector, zip_pf_mbox_intr_handler,
			  0, "zippf mbox", zip);
	if (ret)
		goto free_irq;

	/*Enable all intr */
	zip_reg = ~0ull;
	zip_reg_write(zip, ZIP_PF_ECCE_ENA_W1S, zip_reg);
	zip_reg_write(zip, ZIP_PF_FIFE_ENA_W1S, zip_reg);
	zip_reg_write(zip, ZIP_PF_MBOX_ENA_W1S, zip_reg);

	return 0;

free_irq:
	zip_irq_free(zip);

	return ret;
}

static int zip_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct zippf *zip;
	int    err = -ENOMEM;

	zip = devm_kzalloc(dev, sizeof(*zip), GFP_KERNEL);
	if (!zip)
		return -ENOMEM;

	pci_set_drvdata(pdev, zip);

	zip->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	/* MAP zip configuration registers from bar 0 */
	zip->reg_base = pcim_iomap(pdev, PCI_ZIP_PF_CFG_BAR, 0);
	if (!zip->reg_base) {
		dev_err(dev, "ZIP: Cannot map CSR memory space, aborting");
		err = -ENOMEM;
		goto err_release_regions;
	}
	/* Set ZIP ID */
	zip->id = atomic_add_return(1, &zip_count);
	zip->id -= 1; /* make zip_id 0 as domain ops invoked with zero */

	zip_init(zip);

	/* enable interrupts */
	if (zip_irq_init(zip) < 0)
		atomic_sub_return(1, &zip_count);

	INIT_LIST_HEAD(&zip->list);
	mutex_lock(&octeontx_zip_devices_lock);
	list_add(&zip->list, &octeontx_zip_devices);
	mutex_unlock(&octeontx_zip_devices_lock);

	return 0;

err_release_regions:
	if (zip->reg_base)
		iounmap((void *)zip->reg_base);
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void zip_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct zippf *zip = pci_get_drvdata(pdev);
	struct zippf *curr;

	if (!zip)
		return;

	mutex_lock(&octeontx_zip_devices_lock);
	list_for_each_entry(curr, &octeontx_zip_devices, list) {
		if (curr == zip) {
			list_del(&zip->list);
			break;
		}
	}
	mutex_unlock(&octeontx_zip_devices_lock);

	zip_irq_free(zip);
	zip_sriov_conf(pdev, 0);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, zip);
}

/* Supported devices */
static const struct pci_device_id zip_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_ZIP_PF) },
	{ 0, }  /* end of table */
};

static struct pci_driver zip_driver = {
	.name = DRV_NAME,
	.id_table = zip_id_table,
	.probe = zip_probe,
	.remove = zip_remove,
	.sriov_configure = zip_sriov_conf,
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium OCTEONTX ZIP Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, zip_id_table);

static int __init zip_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);
	return pci_register_driver(&zip_driver);
}

static void __exit zip_cleanup_module(void)
{
	pci_unregister_driver(&zip_driver);
}

module_init(zip_init_module);
module_exit(zip_cleanup_module);
