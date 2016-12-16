/*
 * Driver for MMC and SSD cards for Cavium OCTEON SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012-2016 Cavium Inc.
 */
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <asm/octeon/octeon.h>
#include "cavium_mmc.h"

#define DRV_NAME "octeon_mmc"

#define CVMX_MIO_BOOT_CTL CVMX_ADD_IO_SEG(0x00011800000000D0ull)

extern void l2c_lock_mem_region(u64 start, u64 len);
extern void l2c_unlock_mem_region(u64 start, u64 len);

static void octeon_mmc_acquire_bus(struct cvm_mmc_host *host)
{
	/* Switch the MMC controller onto the bus. */
	down(&octeon_bootbus_sem);
	writeq(0, (void __iomem *)CVMX_MIO_BOOT_CTL);
}

static void octeon_mmc_release_bus(struct cvm_mmc_host *host)
{
	up(&octeon_bootbus_sem);
}

static void octeon_mmc_int_enable(struct cvm_mmc_host *host, u64 val)
{
	writeq(val, host->base + MIO_EMM_INT);
	writeq(val, host->base + MIO_EMM_INT_EN);
}

static void octeon_mmc_dmar_fixup(struct cvm_mmc_host *host,
				  struct mmc_command *cmd,
				  struct mmc_data *data,
				  u64 addr)
{
	if (cmd->opcode != MMC_WRITE_MULTIPLE_BLOCK)
		return;
	if (data->blksz * data->blocks <= 1024)
		return;

	host->n_minus_one = addr + (data->blksz * data->blocks) - 1024;
	l2c_lock_mem_region(host->n_minus_one, 512);
}

static void octeon_mmc_dmar_fixup_done(struct cvm_mmc_host *host)
{
	if (!host->n_minus_one)
		return;
	l2c_unlock_mem_region(host->n_minus_one, 512);
	host->n_minus_one = 0;
}

static int octeon_mmc_probe(struct platform_device *pdev)
{
	struct device_node *cn, *node = pdev->dev.of_node;
	struct cvm_mmc_host *host;
	struct resource	*res;
	void __iomem *base;
	int mmc_irq[9];
	int i, ret = 0;
	u64 val;

	host = devm_kzalloc(&pdev->dev, sizeof(*host), GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	host->dev = &pdev->dev;
	host->acquire_bus = octeon_mmc_acquire_bus;
	host->release_bus = octeon_mmc_release_bus;
	host->int_enable = octeon_mmc_int_enable;
	if (OCTEON_IS_MODEL(OCTEON_CN6XXX) ||
	    OCTEON_IS_MODEL(OCTEON_CNF7XXX)) {
		host->dmar_fixup = octeon_mmc_dmar_fixup;
		host->dmar_fixup_done = octeon_mmc_dmar_fixup_done;
	}

	host->sys_freq = octeon_get_io_clock_rate();

	/* First one is EMM second DMA */
	for (i = 0; i < 2; i++) {
		mmc_irq[i] = platform_get_irq(pdev, i);
		if (mmc_irq[i] < 0)
			return mmc_irq[i];
	}
	host->last_slot = -1;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Platform resource[0] is missing\n");
		return -ENXIO;
	}
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);
	host->base = (void __iomem *)base;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Platform resource[1] is missing\n");
		return -EINVAL;
	}
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);
	host->dma_base = (void __iomem *)base;

	/*
	 * Clear out any pending interrupts that may be left over from
	 * bootloader.
	 */
	val = readq(host->base + MIO_EMM_INT);
	writeq(val, host->base + MIO_EMM_INT);

	ret = devm_request_irq(&pdev->dev, mmc_irq[0],
			       cvm_mmc_interrupt, 0, DRV_NAME, host);
	if (ret < 0) {
		dev_err(&pdev->dev, "Error: devm_request_irq %d\n",
			mmc_irq[0]);
		return ret;
	}

	host->global_pwr_gpiod = devm_gpiod_get_optional(&pdev->dev, "power",
							 GPIOD_OUT_HIGH);
	if (IS_ERR(host->global_pwr_gpiod)) {
		dev_err(&pdev->dev, "Invalid power GPIO\n");
		return PTR_ERR(host->global_pwr_gpiod);
	}

	platform_set_drvdata(pdev, host);

	for_each_child_of_node(node, cn) {
		struct platform_device *slot_pdev;

		slot_pdev = of_platform_device_create(cn, NULL, &pdev->dev);
		ret = cvm_mmc_slot_probe(&slot_pdev->dev, host);
		if (ret) {
			dev_err(&pdev->dev, "Error populating slots\n");
			gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);
			return ret;
		}
	}

	return 0;
}

static int octeon_mmc_remove(struct platform_device *pdev)
{
	union mio_emm_dma_cfg dma_cfg;
	struct cvm_mmc_host *host = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < CAVIUM_MAX_MMC; i++)
		if (host->slot[i])
			cvm_mmc_slot_remove(host->slot[i]);

	dma_cfg.val = readq(host->dma_base + MIO_EMM_DMA_CFG);
	dma_cfg.s.en = 0;
	writeq(dma_cfg.val, host->dma_base + MIO_EMM_DMA_CFG);

	gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);

	return 0;
}

static const struct of_device_id octeon_mmc_match[] = {
	{
		.compatible = "cavium,octeon-6130-mmc",
	},
	{
		.compatible = "cavium,octeon-7890-mmc",
	},
	{},
};
MODULE_DEVICE_TABLE(of, octeon_mmc_match);

static struct platform_driver octeon_mmc_driver = {
	.probe		= octeon_mmc_probe,
	.remove		= octeon_mmc_remove,
	.driver		= {
		.name	= DRV_NAME,
		.of_match_table = octeon_mmc_match,
	},
};

static int __init octeon_mmc_init(void)
{
	return platform_driver_register(&octeon_mmc_driver);
}

static void __exit octeon_mmc_cleanup(void)
{
	platform_driver_unregister(&octeon_mmc_driver);
}

module_init(octeon_mmc_init);
module_exit(octeon_mmc_cleanup);

MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
MODULE_DESCRIPTION("Low-level driver for Cavium OCTEON MMC/SSD card");
MODULE_LICENSE("GPL");
