/*
 * Cavium ThunderX SPI driver.
 *
 * Copyright (C) 2016 Cavium Inc.
 * Authors: Jan Glauber <jglauber@cavium.com>
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spi/spi.h>

#include "spi-cavium.h"

#define DRV_NAME "spi-thunderx"

#define SYS_FREQ_DEFAULT 700000000 /* 700 Mhz */

static int thunderx_spi_probe(struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct spi_master *master;
	struct octeon_spi *p;
	s32 pin = -EINVAL;
	int ret = -ENOENT;

	/* may need to hunt for devtree entry */
	if (!pdev->dev.of_node) {
		struct device_node *np = of_find_node_by_name(NULL, "spi");

		if (IS_ERR(np)) {
			ret = PTR_ERR(np);
			goto error;
		}
		pdev->dev.of_node = np;
		of_node_put(np);
	}

	/* some boards use a GPIO pin to enable CS4-CS7 */
	if (of_find_property(pdev->dev.of_node, "spi-mux-gpios", NULL))
		pin = of_get_named_gpio(pdev->dev.of_node, "spi-mux-gpios", 0);
	if (pin < 0 && pin != -EINVAL)
		ret = pin;
	if (pin == -EPROBE_DEFER)
		goto error;
	if (pin >= 0) {
		ret = devm_gpio_request(dev, pin, "spi-mux");
		if (ret) {
			dev_err(dev, "Cannot get spi-mux (gpio%d): %d\n",
				pin, ret);
			goto error;
		}
	}

	master = spi_alloc_master(dev, sizeof(struct octeon_spi));
	if (!master)
		return -ENOMEM;

	p = spi_master_get_devdata(master);

	ret = pcim_enable_device(pdev);
	if (ret)
		goto error_put;

	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto error_disable;

	p->register_base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!p->register_base) {
		ret = -EINVAL;
		goto error_disable;
	}

	p->regs.config = 0x1000;
	p->regs.status = 0x1008;
	p->regs.tx = 0x1010;
	p->regs.data = 0x1080;
	p->regs.cs_mux = pin;

	/* FIXME: need a proper clocksource object for SCLK */
	p->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(p->clk)) {
		p->clk = devm_clk_get(dev, "sclk");
		p->sys_freq = 0;
	} else {
		ret = clk_prepare_enable(p->clk);
		if (!ret)
			p->sys_freq = clk_get_rate(p->clk);
	}

	if (!p->sys_freq)
		p->sys_freq = SYS_FREQ_DEFAULT;
	dev_info(dev, "Set system clock to %u\n", p->sys_freq);

	master->num_chipselect = (p->regs.cs_mux >= 0) ? 8 : 4;
	master->mode_bits = SPI_CPHA | SPI_CPOL | SPI_CS_HIGH |
			    SPI_LSB_FIRST | SPI_3WIRE;
	master->transfer_one_message = octeon_spi_transfer_one_message;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->max_speed_hz = OCTEON_SPI_MAX_CLOCK_HZ;
	master->dev.of_node = pdev->dev.of_node;

	pci_set_drvdata(pdev, master);

	ret = devm_spi_register_master(dev, master);
	if (ret)
		goto error_disable;

	return 0;

error_disable:
	clk_disable_unprepare(p->clk);
error_put:
	spi_master_put(master);
error:
	return ret;
}

static void thunderx_spi_remove(struct pci_dev *pdev)
{
	struct spi_master *master = pci_get_drvdata(pdev);
	struct octeon_spi *p;

	p = spi_master_get_devdata(master);

	clk_disable_unprepare(p->clk);
	/* Put everything in a known state. */
	if (p)
		writeq(0, p->register_base + OCTEON_SPI_CFG(p));

	pci_disable_device(pdev);
	spi_master_put(master);
}

static const struct pci_device_id thunderx_spi_pci_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xa00b) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, thunderx_spi_pci_id_table);

static struct pci_driver thunderx_spi_driver = {
	.name		= DRV_NAME,
	.id_table	= thunderx_spi_pci_id_table,
	.probe		= thunderx_spi_probe,
	.remove		= thunderx_spi_remove,
};

module_pci_driver(thunderx_spi_driver);

MODULE_DESCRIPTION("Cavium, Inc. ThunderX SPI bus driver");
MODULE_AUTHOR("Jan Glauber");
MODULE_LICENSE("GPL");
