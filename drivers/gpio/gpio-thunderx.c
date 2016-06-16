/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * based on drivers/gpio/gpio-octeon.c
 *
 * Copyright (C) 2016 Cavium Inc.
 */

#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#define DRV_NAME	"thunderx-gpio"
#define DRV_VERSION	"1.0"

#define write_csr(addr, val)	writeq_relaxed(val, (void *)(addr))
#define read_csr(addr)		readq_relaxed((void *)(addr))

#define RX_DAT 0x0
#define TX_SET 0x8
#define TX_CLR 0x10
#define BIT_CFGX 0x400

/**
 * Register (NCB) gpio_bit_cfg#
 *
 * GPIO Bit Configuration Registers Each register provides
 * configuration information for the corresponding GPIO pin.
 */
union gpio_bit_cfgx {
	uint64_t u64;
	struct gpio_bit_cfgx_s {
#ifdef __BIG_ENDIAN_BITFIELD
		uint64_t reserved_26_63        : 38;
		uint64_t pin_sel               : 10;
		uint64_t reserved_13_15        : 3;
		uint64_t tx_od                 : 1;
		uint64_t fil_sel               : 4;
		uint64_t fil_cnt               : 4;
		uint64_t int_type              : 1;
		uint64_t int_en                : 1;
		uint64_t pin_xor               : 1;
		uint64_t tx_oe                 : 1;
#else
		uint64_t tx_oe                 : 1;
		uint64_t pin_xor               : 1;
		uint64_t int_en                : 1;
		uint64_t int_type              : 1;
		uint64_t fil_cnt               : 4;
		uint64_t fil_sel               : 4;
		uint64_t tx_od                 : 1;
		uint64_t reserved_13_15        : 3;
		uint64_t pin_sel               : 10;
		uint64_t reserved_26_63        : 38;
#endif
	} s;
};


/*
 * The address offset of the GPIO configuration register for a given
 * line.
 */
static unsigned int bit_cfg_reg(unsigned int offset)
{
		return 8 * offset + BIT_CFGX;
}

struct thunderx_gpio {
	struct gpio_chip chip;
	void __iomem *register_base;
};

static int thunderx_gpio_dir_in(struct gpio_chip *chip, unsigned offset)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);

	write_csr(gpio->register_base + bit_cfg_reg(offset), 0);
	return 0;
}

static void thunderx_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	u64 mask = 1ull << offset;
	void __iomem *reg = gpio->register_base + (value ? TX_SET : TX_CLR);

	write_csr(reg, mask);
}

static int thunderx_gpio_dir_out(struct gpio_chip *chip, unsigned offset,
			       int pin_sel)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	union gpio_bit_cfgx cfgx;

	cfgx.u64 = 0;

	switch (pin_sel) {
	case  0:
		cfgx.s.tx_oe = 1;
		cfgx.s.pin_sel = 0;
		break;
	default:
		pr_err("invalid pil_sel\n");
		break;
	}

	write_csr(gpio->register_base + bit_cfg_reg(offset), cfgx.u64);
	return 0;
}

static int thunderx_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	u64 read_bits = read_csr(gpio->register_base + RX_DAT);

	return ((1ull << offset) & read_bits) != 0;
}

static int thunderx_gpio_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct thunderx_gpio *gpio;
	struct gpio_chip *chip;
	int err = 0;

	gpio = devm_kzalloc(&pdev->dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;
	chip = &gpio->chip;

	pci_set_drvdata(pdev, gpio);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device: err %d\n", err);
		pci_set_drvdata(pdev, NULL);
		goto out;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed: err %d\n", err);
		goto out;
	}

	gpio->register_base = devm_ioremap(&pdev->dev, pci_resource_start(pdev, 0),
			pci_resource_len(pdev, 0));
	if (!gpio->register_base) {
		dev_err(dev, "Cannot map PCI resource, aborting\n");
		err = -ENOMEM;
		goto out;
	}

	chip->label = "thunderx-gpio";
	chip->parent = &pdev->dev;
	chip->owner = THIS_MODULE;
	chip->base = 0;
	chip->can_sleep = false;
	chip->ngpio = 48;
	chip->direction_input = thunderx_gpio_dir_in;
	chip->get = thunderx_gpio_get;
	chip->direction_output = thunderx_gpio_dir_out;
	chip->set = thunderx_gpio_set;
	err = gpiochip_add(chip);
	if (err)
		goto out;

	dev_info(&pdev->dev, "THUNDERX GPIO driver probed.\n");
	return err;
out:
	devm_iounmap(&pdev->dev, gpio->register_base);
	devm_kfree(&pdev->dev, gpio);
	return err;
}

static void thunderx_gpio_remove(struct pci_dev *pdev)
{
	struct thunderx_gpio *gpio = pci_get_drvdata(pdev);

	gpiochip_remove(&gpio->chip);
	devm_iounmap(&pdev->dev, gpio->register_base);
	devm_kfree(&pdev->dev, gpio);
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
	pci_disable_device(pdev);
}

static const struct pci_device_id thunderx_gpio_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xA00A) },
	{ 0, }  /* end of table */
};

MODULE_DEVICE_TABLE(pci, thunderx_gpio_id_table);

static struct pci_driver thunderx_gpio_driver = {
	.name = DRV_NAME,
	.id_table = thunderx_gpio_id_table,
	.probe = thunderx_gpio_probe,
	.remove = thunderx_gpio_remove,
};

static int __init thunderx_gpio_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);
	return pci_register_driver(&thunderx_gpio_driver);
}

static void __exit thunderx_gpio_cleanup_module(void)
{
	pci_unregister_driver(&thunderx_gpio_driver);
}

module_init(thunderx_gpio_init_module);
module_exit(thunderx_gpio_cleanup_module);

MODULE_DESCRIPTION("Cavium Inc. THUNDERX GPIO Driver");
MODULE_AUTHOR("Ganapatrao kulkarni");
MODULE_LICENSE("GPL");
