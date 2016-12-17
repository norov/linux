/*
 * Driver for MMC and SSD cards for Cavium ThunderX SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Cavium Inc.
 */
#include <linux/dma-mapping.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include "cavium_mmc.h"

#define DRV_NAME "thunderx_mmc"

static void thunder_mmc_acquire_bus(struct cvm_mmc_host *host)
{
	down(&host->mmc_serializer);
}

static void thunder_mmc_release_bus(struct cvm_mmc_host *host)
{
	up(&host->mmc_serializer);
}

static void thunder_mmc_int_enable(struct cvm_mmc_host *host, u64 val)
{
	writeq(val, host->base + MIO_EMM_INT);
	writeq(val, host->base + MIO_EMM_INT_EN_SET);
}

static int thunder_mmc_register_interrupts(struct cvm_mmc_host *host,
					   struct pci_dev *pdev)
{
	int ret, i;

	host->msix_count = pci_msix_vec_count(pdev);
	host->mmc_msix = devm_kzalloc(&pdev->dev,
		(sizeof(struct msix_entry)) * host->msix_count, GFP_KERNEL);
	if (!host->mmc_msix)
		return -ENOMEM;

	for (i = 0; i < host->msix_count; i++)
		host->mmc_msix[i].entry = i;

	ret = pci_enable_msix(pdev, host->mmc_msix, host->msix_count);
	if (ret)
		return ret;

	/* register interrupts */
	for (i = 0; i < host->msix_count; i++) {
		ret = devm_request_irq(&pdev->dev, host->mmc_msix[i].vector,
				       cvm_mmc_interrupt,
				       0, DRV_NAME, host);
		if (ret)
			return ret;
	}
	return 0;
}

static int thunder_mmc_probe(struct pci_dev *pdev,
			     const struct pci_device_id *id)
{
	struct device_node *node = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	struct device_node *child_node;
	struct cvm_mmc_host *host;
	int ret;

	host = devm_kzalloc(dev, sizeof(*host), GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	pci_set_drvdata(pdev, host);
	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		return ret;

	host->base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!host->base)
		return -EINVAL;

	/* On ThunderX these are identical */
	host->dma_base = host->base;

	host->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(host->clk))
		return PTR_ERR(host->clk);

	ret = clk_prepare_enable(host->clk);
	if (ret)
		return ret;
	host->sys_freq = clk_get_rate(host->clk);

	spin_lock_init(&host->irq_handler_lock);
	sema_init(&host->mmc_serializer, 1);

	host->dev = dev;
	host->acquire_bus = thunder_mmc_acquire_bus;
	host->release_bus = thunder_mmc_release_bus;
	host->int_enable = thunder_mmc_int_enable;

	host->use_sg = true;
	host->big_dma_addr = true;
	host->need_irq_handler_lock = true;
	host->last_slot = -1;

	ret = dma_set_mask(dev, DMA_BIT_MASK(48));
	if (ret)
		goto error;

	/*
	 * Clear out any pending interrupts that may be left over from
	 * bootloader. Writing 1 to the bits clears them.
	 */
	writeq(127, host->base + MIO_EMM_INT_EN);
	writeq(3, host->base + MIO_EMM_DMA_INT_ENA_W1C);
	/* Clear DMA FIFO */
	writeq(BIT_ULL(16), host->base + MIO_EMM_DMA_FIFO_CFG);

	ret = thunder_mmc_register_interrupts(host, pdev);
	if (ret)
		goto error;

	host->global_pwr_gpiod = devm_gpiod_get_optional(&pdev->dev, "power",
							 GPIOD_OUT_LOW);
	if (IS_ERR(host->global_pwr_gpiod)) {
		ret = PTR_ERR(host->global_pwr_gpiod);
		goto error;
	}

	for_each_child_of_node(node, child_node) {
		/*
		 * XXX hack: mmc_of_parse looks only at the current device's
		 * DT node. That means we require one device per slot with
		 * it's node pointing to the slot. The easiest way to get this
		 * is using of_platform_device_create. Not sure what a proper
		 * solution is, maybe extend mmc_of_parse to handle multiple
		 * slots? --jang
		 */
		struct platform_device *slot_pdev;

		slot_pdev = of_platform_device_create(child_node, NULL,
						      &pdev->dev);
		if (!slot_pdev)
			continue;
		ret = cvm_mmc_slot_probe(&slot_pdev->dev, host);
		if (ret) {
			gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);
			goto error;
		}
	}
	dev_info(dev, "probed\n");
	return 0;

error:
	clk_disable_unprepare(host->clk);
	return ret;
}

static void thunder_mmc_remove(struct pci_dev *pdev)
{
	struct cvm_mmc_host *host = pci_get_drvdata(pdev);
	union mio_emm_dma_cfg dma_cfg;
	int i;

	for (i = 0; i < CAVIUM_MAX_MMC; i++)
		if (host->slot[i])
			cvm_mmc_slot_remove(host->slot[i]);

	dma_cfg.val = readq(host->dma_base + MIO_EMM_DMA_CFG);
	dma_cfg.s.en = 0;
	writeq(dma_cfg.val, host->dma_base + MIO_EMM_DMA_CFG);

	gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);
	clk_disable_unprepare(host->clk);
}

static const struct pci_device_id thunder_mmc_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xa010) },
	{ 0, }  /* end of table */
};

static struct pci_driver thunder_mmc_driver = {
	.name = DRV_NAME,
	.id_table = thunder_mmc_id_table,
	.probe = thunder_mmc_probe,
	.remove = thunder_mmc_remove,
};

static int __init thunder_mmc_init_module(void)
{
	return pci_register_driver(&thunder_mmc_driver);
}

static void __exit thunder_mmc_exit_module(void)
{
	pci_unregister_driver(&thunder_mmc_driver);
}

module_init(thunder_mmc_init_module);
module_exit(thunder_mmc_exit_module);

MODULE_AUTHOR("Cavium Inc.");
MODULE_DESCRIPTION("Cavium ThunderX eMMC Driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, thunder_mmc_id_table);
