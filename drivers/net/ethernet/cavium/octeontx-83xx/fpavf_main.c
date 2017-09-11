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
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/iommu.h>

#include "fpa.h"

#define DRV_NAME "octeontx-fpavf"
#define DRV_VERSION "1.0"

static int setup_test;
module_param(setup_test, int, 0644);
MODULE_PARM_DESC(setup_test, "does a test after doing setup");

static DEFINE_SPINLOCK(octeontx_fpavf_devices_lock);
static DEFINE_SPINLOCK(octeontx_fpavf_alloc_lock);
static LIST_HEAD(octeontx_fpavf_devices);

/* In Cavium OcteonTX SoCs, all accesses to the device registers are
 * implicitly strongly ordered.
 * So writeq_relaxed() and readq_relaxed() are safe to use
 * with out any memory barriers.
 */

/* Register read/write APIs */
static void fpavf_reg_write(struct fpavf *fpa, u64 offset, u64 val)
{
	writeq_relaxed(val, fpa->reg_base + offset);
}

static u64 fpavf_reg_read(struct fpavf *fpa, u64 offset)
{
	return readq_relaxed(fpa->reg_base + offset);
}

static void fpa_vf_free(struct fpavf *fpa, u32 aura, u64 addr, u32 dwb_count)
{
	u64 free_addr = FPA_FREE_ADDRS_S(FPA_VF_VHAURA_OP_FREE(aura),
			dwb_count);

	fpavf_reg_write(fpa, free_addr, addr);
}

static u64 fpa_vf_alloc(struct fpavf *fpa, u32 aura)
{
	u64 addr = 0;

	addr = fpavf_reg_read(fpa, FPA_VF_VHAURA_OP_ALLOC(aura));

	return addr;
}

static inline u64 fpa_vf_iova_to_phys(struct fpavf *fpa, dma_addr_t dma_addr)
{
	/* Translation is installed only when IOMMU is present */
	if (fpa->iommu_domain)
		return iommu_iova_to_phys(fpa->iommu_domain, dma_addr);
	return dma_addr;
}

static int fpa_vf_do_test(struct fpavf *fpa, u64 num_buffers)
{
	u64 *buf;
	u64 avail;
	int i;

	buf = kcalloc(num_buffers, sizeof(u64), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, sizeof(u64) * num_buffers);

	i = 0;
	while (true) {
		buf[i] = fpa_vf_alloc(fpa, 0);
		if (!buf[i])
			break;
		i++;
	}

	if (i != num_buffers) {
		dev_err(&fpa->pdev->dev, "Didn't get enough buffers");
		dev_err(&fpa->pdev->dev, "expected :%llu got %d\n",
			num_buffers, i);
	}

	while (i) {
		fpa_vf_free(fpa, 0, buf[i - 1], 0);
		i--;
	}
	avail = fpavf_reg_read(fpa, FPA_VF_VHPOOL_AVAILABLE(0));
	dev_info(&fpa->pdev->dev, "Fpa vf setup test done::");
	dev_info(&fpa->pdev->dev, " requested:%llu avail_count:%llu\n",
		 num_buffers, avail);
	return 0;
}

static int fpa_vf_addbuffers(struct fpavf *fpa, u64 num_buffers, u32 buf_len)
{
	dma_addr_t iova, first_addr = -1, last_addr = 0;
	void *addr;
	struct page *p;

	while (num_buffers) {
		p = alloc_page(GFP_KERNEL | __GFP_NOWARN);
		if (!p) {
			dev_err(&fpa->pdev->dev, "failed to allocate vhpool buffers\n");
			return -ENOMEM;
		}
		addr = page_address(p);
		/*TODO: add dma mappings here if needed.*/
		iova = dma_map_single(&fpa->pdev->dev, addr, PAGE_SIZE,
				      DMA_BIDIRECTIONAL);
		fpa_vf_free(fpa, 0, iova, 0);
		num_buffers--;
		if (iova > last_addr)
			last_addr = iova;
		if (iova < first_addr)
			first_addr = iova;
	}
	fpavf_reg_write(fpa, FPA_VF_VHPOOL_START_ADDR(0), first_addr);
	fpavf_reg_write(fpa, FPA_VF_VHPOOL_END_ADDR(0),
			last_addr + PAGE_SIZE - 1);
	return 0;
}

static int fpa_vf_addmemory(struct fpavf *fpa, u64 num_buffers, u32 buf_len)
{
	dma_addr_t iova,  first_addr = -1, last_addr = 0;
	u32 buffs_per_chunk, chunk_size;
	u32 i, j, ret = 0;

	chunk_size = MAX_ORDER_NR_PAGES * PAGE_SIZE;
	if (chunk_size > num_buffers * buf_len)
		chunk_size = num_buffers * buf_len;

	buffs_per_chunk = chunk_size / buf_len;
	fpa->vhpool_memvec_size = (num_buffers + buffs_per_chunk - 1) /
				   buffs_per_chunk;
	if (fpa->vhpool_memvec_size > (PAGE_SIZE / sizeof(struct memvec *))) {
		dev_err(&fpa->pdev->dev,
			"unable to allocate memory for pointers\n");
		goto err_unlock;
	}

	fpa->vhpool_memvec = (struct memvec *)__get_free_page(GFP_KERNEL |
							      __GFP_NOWARN);
	if (!fpa->vhpool_memvec) {
		dev_err(&fpa->pdev->dev, "failed to allocate page\n");
		return -ENOMEM;
	}
	memset(fpa->vhpool_memvec, 0, PAGE_SIZE);

	for (i = 0; i < fpa->vhpool_memvec_size; i++) {
		fpa->vhpool_memvec[i].size = chunk_size;
		fpa->vhpool_memvec[i].addr =
			dma_zalloc_coherent(&fpa->pdev->dev,
					    fpa->vhpool_memvec[i].size,
					    &fpa->vhpool_memvec[i].iova,
					    GFP_KERNEL);
		if (!fpa->vhpool_memvec[i].addr) {
			dev_err(&fpa->pdev->dev,
				"failed to allocate vhpool memory\n");
			ret = -ENOMEM;
			goto err_unlock;
		}

		fpa->vhpool_memvec[i].in_use = true;
		if (fpa->vhpool_memvec[i].iova > last_addr)
			last_addr = fpa->vhpool_memvec[i].iova;
		if (fpa->vhpool_memvec[i].iova < first_addr)
			first_addr = fpa->vhpool_memvec[i].iova;
	}

	fpavf_reg_write(fpa, FPA_VF_VHPOOL_START_ADDR(0), first_addr);
	fpavf_reg_write(fpa, FPA_VF_VHPOOL_END_ADDR(0),
			last_addr + chunk_size - 1);

	for (i = 0; i < fpa->vhpool_memvec_size && num_buffers > 0; i++) {
		iova = fpa->vhpool_memvec[i].iova;
		for (j = 0; j < buffs_per_chunk; j++) {
			fpa_vf_free(fpa, 0, iova, 0);
			iova += buf_len;
			num_buffers--;
			if (num_buffers == 0)
				break;
		}
	}

	return 0;

err_unlock:

	for (i = 0; i < fpa->vhpool_memvec_size; i++)
		if (fpa->vhpool_memvec[i].in_use) {
			dma_free_coherent(&fpa->pdev->dev,
					  fpa->vhpool_memvec[i].size,
					  fpa->vhpool_memvec[i].addr,
					  fpa->vhpool_memvec[i].iova);
			fpa->vhpool_memvec[i].in_use = false;
		}

	fpa->vhpool_memvec_size = 0x0;
	return ret;
}

static int fpa_vf_setup(struct fpavf *fpa, u64 num_buffers, u32 buf_len,
			u32 flags)
{
	struct mbox_fpa_cfg cfg;
	struct mbox_hdr hdr;
	union mbox_data req;
	union mbox_data resp;
	u64 reg;
	int ret;

	buf_len = round_up(buf_len, FPA_LN_SIZE);
	fpa->pool_size = (num_buffers + fpa->stack_ln_ptrs - 1)
			  / fpa->stack_ln_ptrs * FPA_LN_SIZE;

	fpa->pool_addr = dma_zalloc_coherent(&fpa->pdev->dev, fpa->pool_size,
			&fpa->pool_iova, GFP_KERNEL);

	if (!fpa->pool_addr) {
		dev_err(&fpa->pdev->dev, "failed to allocate Pool stack\n");
		return -ENOMEM;
	}

	fpa->num_buffers = num_buffers;
	fpa->alloc_count = ((atomic_t) { (0) });
	fpa->alloc_thold = (num_buffers * 10) / 100;
	fpa->buf_len = buf_len;
	fpa->flags = flags;

	req.data = 0;
	hdr.coproc = FPA_COPROC;
	hdr.msg = FPA_CONFIGSET;
	hdr.vfid = fpa->subdomain_id;

	/*POOL setup */
	reg = POOL_BUF_SIZE(buf_len / FPA_LN_SIZE) | POOL_BUF_OFFSET(0) |
		POOL_LTYPE(0x2) | POOL_STYPE(0) | POOL_SET_NAT_ALIGN | POOL_ENA;

	cfg.aid = 0;
	cfg.pool_cfg = reg;
	cfg.pool_stack_base = fpa->pool_iova;
	cfg.pool_stack_end = fpa->pool_iova + fpa->pool_size;
	cfg.aura_cfg = (1 << 9);

	ret = fpa->master->send_message(&hdr, &req, &resp, fpa->master_data,
					&cfg);
	if (ret || hdr.res_code)
		return -EINVAL;

	if (flags & FPA_VF_FLAG_CONT_MEM)
		fpa_vf_addmemory(fpa, num_buffers, buf_len);
	else
		fpa_vf_addbuffers(fpa, num_buffers, buf_len);

	req.data = 0;
	hdr.coproc = FPA_COPROC;
	hdr.msg = FPA_START_COUNT;
	hdr.vfid = fpa->subdomain_id;
	ret = fpa->master->send_message(&hdr, &req, &resp, fpa->master_data,
					NULL);
	if (ret || hdr.res_code)
		return -EINVAL;

	if (setup_test)
		fpa_vf_do_test(fpa, num_buffers);

	/*Setup THRESHOLD*/
	fpavf_reg_write(fpa, FPA_VF_VHAURA_CNT_THRESHOLD(0), num_buffers - 1);

	return 0;
}

static int fpa_vf_teardown(struct fpavf *fpa)
{
	union mbox_data resp;
	struct mbox_hdr hdr;
	union mbox_data req;
	struct memvec *memvec;
	u64 av, iova, *buf;
	int ret, i;
	bool found;

	if (!fpa)
		return -ENODEV;

	req.data = 0;
	hdr.coproc = FPA_COPROC;
	hdr.msg = FPA_STOP_COUNT;
	hdr.vfid = fpa->subdomain_id;
	ret = fpa->master->send_message(&hdr, &req, &resp, fpa->master_data,
					NULL);
	if (ret || hdr.res_code)
		return -EINVAL;

	/* Remove limits on the aura */
	fpavf_reg_write(fpa, FPA_VF_VHAURA_CNT_THRESHOLD(0), -1);
	fpavf_reg_write(fpa, FPA_VF_VHAURA_CNT_LIMIT(0), -1);
	/* There can be two types of memory allocation for FPA VF:
	 * contiguous (FPA_VF_FLAG_CONT_MEM) or not (FPA_VF_FLAG_DISC_MEM).
	 * If contiguous memory was requested, then a segment of memory was
	 * allocated at address fpa->vhpool_addr of size fpa->vhpool_size.
	 * For each address from that region taken out of the pool, do not
	 * free it, instead free the whole segment at the end.
	 * In other case (or if fpa->refill() was called) each buffer is a
	 * single page. For that case, free each buffer as it's taken out of the
	 * pool.
	 */
	av = fpavf_reg_read(fpa, FPA_VF_VHPOOL_AVAILABLE(0));
	while (av) {
		found = false;
		iova = fpa_vf_alloc(fpa, 0);
		for (i = 0; i < fpa->vhpool_memvec_size; i++) {
			memvec = &fpa->vhpool_memvec[i];
			if (iova >= memvec->iova &&
			    iova < memvec->iova + memvec->size &&
			    fpa->flags & FPA_VF_FLAG_CONT_MEM) {
				av = fpavf_reg_read(fpa,
						    FPA_VF_VHPOOL_AVAILABLE(0));
				found = true;
				break;
			}
		}

		if (found)
			continue;

		/* If there is a NAT_ALIGN bug here, it means that we'll get a
		 * different address from FPA than the beginning of the page.
		 * Therefore we're aligning the address to page size.
		 */
		if (iova == 0) {
			dev_err(&fpa->pdev->dev,
				"NULL buffer in pool %d of domain %d\n",
				fpa->subdomain_id, fpa->domain_id);
			av = fpavf_reg_read(fpa, FPA_VF_VHPOOL_AVAILABLE(0));
			continue;
		}
		iova = PAGE_ALIGN(iova);
		dma_unmap_single(&fpa->pdev->dev, iova, PAGE_SIZE,
				 DMA_BIDIRECTIONAL);
		buf = phys_to_virt(fpa_vf_iova_to_phys(fpa, iova));
		free_page((u64)buf);
		av = fpavf_reg_read(fpa, FPA_VF_VHPOOL_AVAILABLE(0));
	}

	/* If allocation was contiguous, free that region */
	if (fpa->flags & FPA_VF_FLAG_CONT_MEM) {
		for (i = 0; i < fpa->vhpool_memvec_size; i++) {
			if (fpa->vhpool_memvec[i].in_use) {
				dma_free_coherent(&fpa->pdev->dev,
						  fpa->vhpool_memvec[i].size,
						  fpa->vhpool_memvec[i].addr,
						  fpa->vhpool_memvec[i].iova);
				fpa->vhpool_memvec[i].in_use = false;
			}

			fpa->vhpool_memvec_size = 0x0;
			free_page((unsigned long)fpa->vhpool_memvec);
		}
	}

	/* Finally free the stack */
	dma_free_coherent(&fpa->pdev->dev, fpa->pool_size,
			  fpa->pool_addr, fpa->pool_iova);
	return 0;
}

static struct fpavf *fpa_vf_get(u16 domain_id, u16 subdomain_id,
				struct octeontx_master_com_t *master,
				void *master_data)
{
	struct mbox_hdr hdr;
	struct fpavf *fpa = NULL;
	struct fpavf *curr;
	union mbox_data req;
	union mbox_data resp;
	u64 reg;
	u32 d_id, sd_id;
	int ret;

	spin_lock(&octeontx_fpavf_devices_lock);
	list_for_each_entry(curr, &octeontx_fpavf_devices, list) {
		if (curr->domain_id == domain_id &&
		    curr->subdomain_id == subdomain_id) {
			fpa = curr;
			break;
		}
	}
	spin_unlock(&octeontx_fpavf_devices_lock);

	if (!fpa) {
		/*Try sending identify to PF*/
		req.data = 0;
		hdr.coproc = FPA_COPROC;
		hdr.msg = IDENTIFY;
		hdr.vfid = subdomain_id;
		ret = master->send_message(&hdr, &req, &resp,
					master_data, NULL);
		if (ret)
			return NULL;

		spin_lock(&octeontx_fpavf_devices_lock);
		list_for_each_entry(curr, &octeontx_fpavf_devices, list) {
			reg = fpavf_reg_read(curr, FPA_VF_VHPOOL_START_ADDR(0));

			if (reg)
				continue;

			/* get did && sdid */
			reg = fpavf_reg_read(curr,
					     FPA_VF_VHAURA_CNT_THRESHOLD(0));

			reg = reg >> 8;
			d_id = (reg & 0xffff);
			sd_id = ((reg >> 16) & 0xffff);
			if (domain_id == d_id && subdomain_id == sd_id) {
				fpa = curr;
				break;
			}
		}
		spin_unlock(&octeontx_fpavf_devices_lock);
	}

	if (fpa) {
		reg = fpavf_reg_read(fpa,
				     FPA_VF_VHPOOL_THRESHOLD(0));
		fpa->domain_id = domain_id;
		fpa->subdomain_id = subdomain_id;
		fpa->master = master;
		fpa->master_data = master_data;
		fpa->stack_ln_ptrs = reg;
	}

	return fpa;
}

static int fpa_vf_refill(struct fpavf *fpa)
{
	u64 alloc_count;

	spin_lock(&octeontx_fpavf_alloc_lock);
	alloc_count = atomic_read(&fpa->alloc_count);
	if (alloc_count >= fpa->alloc_thold)
		fpa_vf_addbuffers(fpa, alloc_count, fpa->buf_len);

	atomic_sub_return(alloc_count, &fpa->alloc_count);
	spin_unlock(&octeontx_fpavf_alloc_lock);
	return alloc_count;
}

static void fpa_vf_add_alloc(struct fpavf *fpa, int count)
{
	atomic_add_return(count, &fpa->alloc_count);
}

struct fpavf_com_s fpavf_com = {
	.get = fpa_vf_get,
	.setup = fpa_vf_setup,
	.free = fpa_vf_free,
	.alloc = fpa_vf_alloc,
	.refill = fpa_vf_refill,
	.add_alloc = fpa_vf_add_alloc,
	.teardown = fpa_vf_teardown,
};
EXPORT_SYMBOL(fpavf_com);

static irqreturn_t fpa_vf_intr_handler (int irq, void *fpa_irq)
{
	struct fpavf *fpa = (struct fpavf *)fpa_irq;
	u64 vf_int = fpavf_reg_read(fpa, FPA_VF_INT(0));

	if (!(vf_int & 0x8))
		dev_err(&fpa->pdev->dev, "VF interrupt: %llx\n", vf_int);

	/* clear irq status */
	fpavf_reg_write(fpa, FPA_VF_INT(0), vf_int);

	return IRQ_HANDLED;
}

static int fpavf_irq_init(struct fpavf *fpa)
{
	u64 vf_int = 0xFFFF0000007f;
	int i, ret;

	/*clear irq status */
	fpavf_reg_write(fpa, FPA_VF_INT_ENA_W1C(0), vf_int);

	ret = FPA_VF_MSIX_COUNT;
	if (ret < 0) {
		dev_err(&fpa->pdev->dev, "Failed to get MSIX table size\n");
		return ret;
	}

	fpa->msix_entries = devm_kzalloc(&fpa->pdev->dev,
			ret * sizeof(struct msix_entry), GFP_KERNEL);
	if (!fpa->msix_entries)
		return -ENOMEM;
	for (i = 0; i < ret; i++)
		fpa->msix_entries[i].entry = i;

	ret = pci_enable_msix_exact(fpa->pdev, fpa->msix_entries, ret);
	if (ret < 0) {
		dev_err(&fpa->pdev->dev, "Enabling msix failed\n");
		return ret;
	}

	/* register GEN intr handler */
	ret = request_irq(fpa->msix_entries[0].vector, fpa_vf_intr_handler,
			  0, "fpavf", fpa);
	if (ret)
		return ret;

	/* it's time to enable interrupts*/
	fpavf_reg_write(fpa, FPA_VF_INT_ENA_W1S(0), vf_int);

	return 0;
}

static void fpavf_irq_free(struct fpavf *fpa)
{
	u64 vf_int = 0xFFFF0000007f;

	/*clear GEN irq status */
	fpavf_reg_write(fpa, FPA_VF_INT_ENA_W1C(0), vf_int);

	free_irq(fpa->msix_entries[0].vector, fpa);
	pci_disable_msix(fpa->pdev);
	devm_kfree(&fpa->pdev->dev, fpa->msix_entries);
}

static int fpavf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct fpavf *fpa;
	int err = -ENOMEM;

	fpa = devm_kzalloc(dev, sizeof(*fpa), GFP_KERNEL);
	if (!fpa)
		return err;

	pci_set_drvdata(pdev, fpa);
	fpa->pdev = pdev;

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

	/*Map CFG registers */
	fpa->reg_base = pcim_iomap(pdev, PCI_FPA_VF_CFG_BAR, 0);
	if (!fpa->reg_base) {
		dev_err(dev, "Can't map CFG space\n");
		err = -ENOMEM;
		return err;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		return err;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA\n");
		return err;
	}

	err = fpavf_irq_init(fpa);
	if (err) {
		dev_err(dev, "failed init irqs\n");
		err = -EINVAL;
		return err;
	}

	/* Get iommu domain for iova to physical addr conversion */
	fpa->iommu_domain = iommu_get_domain_for_dev(&pdev->dev);

	INIT_LIST_HEAD(&fpa->list);
	spin_lock(&octeontx_fpavf_devices_lock);
	list_add(&fpa->list, &octeontx_fpavf_devices);
	spin_unlock(&octeontx_fpavf_devices_lock);

	return 0;
}

static void fpavf_remove(struct pci_dev *pdev)
{
	struct fpavf *fpa = pci_get_drvdata(pdev);
	struct fpavf *curr;

	if (!fpa)
		return;

	spin_lock(&octeontx_fpavf_devices_lock);
	list_for_each_entry(curr, &octeontx_fpavf_devices, list) {
		if (curr == fpa) {
			list_del(&fpa->list);
			break;
		}
	}
	spin_unlock(&octeontx_fpavf_devices_lock);

	fpavf_irq_free(fpa);
	pcim_iounmap(pdev, fpa->reg_base);
	pci_disable_device(pdev);
	pci_release_regions(pdev);

	devm_kfree(&pdev->dev, fpa);
}

/* devices supported */
static const struct pci_device_id fpavf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_FPA_VF) },
	{ 0, }  /* end of table */
};

static struct pci_driver fpavf_driver = {
	.name = DRV_NAME,
	.id_table = fpavf_id_table,
	.probe = fpavf_probe,
	.remove = fpavf_remove,
};

MODULE_AUTHOR("Tirumalesh Chalamarla");
MODULE_DESCRIPTION("Cavium OCTEONTX FPA Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, fpavf_id_table);

static int __init fpavf_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&fpavf_driver);
}

static void __exit fpavf_cleanup_module(void)
{
	pci_unregister_driver(&fpavf_driver);
}

module_init(fpavf_init_module);
module_exit(fpavf_cleanup_module);
