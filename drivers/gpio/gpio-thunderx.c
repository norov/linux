/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016, 2017 Cavium Inc.
 */

#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spinlock.h>


#define GPIO_RX_DAT	0x0
#define GPIO_TX_SET	0x8
#define GPIO_TX_CLR	0x10
#define GPIO_CONST	0x90
#define  GPIO_CONST_GPIOS_MASK 0xff
#define GPIO_BIT_CFG	0x400
#define  GPIO_BIT_CFG_TX_OE		BIT(0)
#define  GPIO_BIT_CFG_PIN_XOR		BIT(1)
#define  GPIO_BIT_CFG_INT_EN		BIT(2)
#define  GPIO_BIT_CFG_INT_TYPE		BIT(3)
#define  GPIO_BIT_CFG_FIL_CNT_SHIFT	4
#define  GPIO_BIT_CFG_FIL_SEL_SHIFT	8
#define  GPIO_BIT_CFG_TX_OD		BIT(12)
#define  GPIO_BIT_CFG_PIN_SEL_MASK	GENMASK(25, 16)
#define GPIO_INTR	0x800
#define  GPIO_INTR_INTR			BIT(0)
#define  GPIO_INTR_INTR_W1S		BIT(1)
#define  GPIO_INTR_ENA_W1C		BIT(2)
#define  GPIO_INTR_ENA_W1S		BIT(3)
#define GPIO_2ND_BANK	0x1400

#define GLITCH_FILTER_400NS ((4ull << GPIO_BIT_CFG_FIL_SEL_SHIFT) | \
			     (9ull << GPIO_BIT_CFG_FIL_CNT_SHIFT))

static unsigned int bit_cfg_reg(unsigned int line)
{
	return 8 * line + GPIO_BIT_CFG;
}

static unsigned int intr_reg(unsigned int line)
{
	return 8 * line + GPIO_INTR;
}

struct thunderx_gpio;

struct thunderx_irqdev {
	struct thunderx_gpio	*gpio;
	char			*name;
	unsigned int		line;
};

struct thunderx_gpio {
	struct gpio_chip	chip;
	u8 __iomem		*register_base;
	struct msix_entry	*msix_entries;
	struct thunderx_irqdev	*irqdev_entries;
	raw_spinlock_t		lock;
	unsigned long		invert_mask[2];
	unsigned long		od_mask[2];
	int			base_msi;
};


/*
 * Check (and WARN) that the pin is available for GPIO.  We will not
 * allow modification of the state of non-GPIO pins from this driver.
 */
static bool thunderx_gpio_is_gpio(struct thunderx_gpio *gpio,
				  unsigned int line)
{
	u64 bit_cfg = readq(gpio->register_base + bit_cfg_reg(line));
	bool rv = (bit_cfg & GPIO_BIT_CFG_PIN_SEL_MASK) == 0;

	WARN_RATELIMIT(!rv, "Pin %d not available for GPIO\n", line);

	return rv;
}

static int thunderx_gpio_dir_in(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);

	if (!thunderx_gpio_is_gpio(gpio, line))
		return -EIO;

	raw_spin_lock(&gpio->lock);
	clear_bit(line, gpio->invert_mask);
	clear_bit(line, gpio->od_mask);
	writeq(GLITCH_FILTER_400NS, gpio->register_base + bit_cfg_reg(line));
	raw_spin_unlock(&gpio->lock);
	return 0;
}

static void thunderx_gpio_set(struct gpio_chip *chip, unsigned int line,
			      int value)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	int bank = line / 64;
	int bank_bit = line % 64;

	void __iomem *reg = gpio->register_base +
		(bank * GPIO_2ND_BANK) + (value ? GPIO_TX_SET : GPIO_TX_CLR);

	writeq(1ull << bank_bit, reg);
}

static int thunderx_gpio_dir_out(struct gpio_chip *chip, unsigned int line,
				 int value)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	u64 bit_cfg = GPIO_BIT_CFG_TX_OE;

	if (!thunderx_gpio_is_gpio(gpio, line))
		return -EIO;

	raw_spin_lock(&gpio->lock);

	thunderx_gpio_set(chip, line, value);

	if (test_bit(line, gpio->invert_mask))
		bit_cfg |= GPIO_BIT_CFG_PIN_XOR;

	if (test_bit(line, gpio->od_mask))
		bit_cfg |= GPIO_BIT_CFG_TX_OD;

	writeq(bit_cfg, gpio->register_base + bit_cfg_reg(line));

	raw_spin_unlock(&gpio->lock);
	return 0;
}

/*
 * Weird, setting open-drain mode causes signal inversion.  Note this
 * so we can compensate in the dir_out function.
 */
static int thunderx_gpio_set_single_ended(struct gpio_chip *chip,
					  unsigned int line,
					  enum single_ended_mode mode)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);

	if (mode == LINE_MODE_OPEN_SOURCE)
		return -ENOTSUPP;

	if (!thunderx_gpio_is_gpio(gpio, line))
		return -EIO;

	raw_spin_lock(&gpio->lock);
	if (mode == LINE_MODE_OPEN_DRAIN) {
		set_bit(line, gpio->invert_mask);
		set_bit(line, gpio->od_mask);
	} else {
		clear_bit(line, gpio->invert_mask);
		clear_bit(line, gpio->od_mask);
	}
	raw_spin_unlock(&gpio->lock);

	return 0;
}

static int thunderx_gpio_get(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	int bank = line / 64;
	int bank_bit = line % 64;
	u64 read_bits = readq(gpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_RX_DAT);

	read_bits >>= bank_bit;

	if (test_bit(line, gpio->invert_mask))
		return !(read_bits & 1);
	else
		return read_bits & 1;
}

static void thunderx_gpio_set_multiple(struct gpio_chip *chip,
				       unsigned long *mask,
				       unsigned long *bits)
{
	int bank;
	u64 set_bits, clear_bits;
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);

	for (bank = 0; bank <= chip->ngpio / 64; bank++) {
		set_bits = bits[bank] & mask[bank];
		clear_bits = ~bits[bank] & mask[bank];
		writeq(set_bits, gpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_TX_SET);
		writeq(clear_bits, gpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_TX_CLR);
	}
}

static irqreturn_t thunderx_gpio_chain_handler(int irq, void *dev)
{
	struct thunderx_irqdev *irqdev = dev;
	int chained_irq;
	int ret;

	chained_irq = irq_find_mapping(irqdev->gpio->chip.irqdomain,
				       irqdev->line);
	if (!chained_irq)
		return IRQ_NONE;

	ret = generic_handle_irq(chained_irq);

	return ret ? IRQ_NONE : IRQ_HANDLED;
}

static int thunderx_gpio_irq_request_resources(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;
	struct thunderx_irqdev *irqdev;
	int err;

	if (!thunderx_gpio_is_gpio(gpio, line))
		return -EIO;

	irqdev = gpio->irqdev_entries + line;

	irqdev->gpio = gpio;
	irqdev->line = line;
	irqdev->name = devm_kasprintf(chip->parent, GFP_KERNEL,
				      "gpio-%d", line + chip->base);

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));

	err = devm_request_irq(chip->parent, gpio->msix_entries[line].vector,
			       thunderx_gpio_chain_handler, IRQF_NO_THREAD, irqdev->name, irqdev);
	return err;
}

static void thunderx_gpio_irq_release_resources(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;
	struct thunderx_irqdev *irqdev;

	irqdev = gpio->irqdev_entries + line;

	/*
	 * The request_resources/release_resources functions may be
	 * called multiple times in the lifitime of the driver, so we
	 * need to clean up the devm_* things to avoid a resource
	 * leak.
	 */
	devm_free_irq(chip->parent, gpio->msix_entries[line].vector, irqdev);

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));

	devm_kfree(chip->parent, irqdev->name);
}

static void thunderx_gpio_irq_ack(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_INTR,
	       gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_irq_mask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_irq_mask_ack(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1C | GPIO_INTR_INTR,
	       gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_irq_unmask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1S, gpio->register_base + intr_reg(line));
}

static int thunderx_gpio_irq_set_type(struct irq_data *data,
				      unsigned int flow_type)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;
	u64 bit_cfg;

	irqd_set_trigger_type(data, flow_type);

	bit_cfg = GLITCH_FILTER_400NS | GPIO_BIT_CFG_INT_EN;

	if (flow_type & IRQ_TYPE_EDGE_BOTH) {
		irq_set_handler_locked(data, handle_edge_irq);
		bit_cfg |= GPIO_BIT_CFG_INT_TYPE;
	} else {
		irq_set_handler_locked(data, handle_level_irq);
	}

	raw_spin_lock(&gpio->lock);
	if (flow_type & (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_LEVEL_LOW)) {
		bit_cfg |= GPIO_BIT_CFG_PIN_XOR;
		set_bit(line, gpio->invert_mask);
	} else {
		clear_bit(line, gpio->invert_mask);
	}
	clear_bit(line, gpio->od_mask);
	writeq(bit_cfg, gpio->register_base + bit_cfg_reg(line));
	raw_spin_unlock(&gpio->lock);

	return IRQ_SET_MASK_OK;
}

/*
 * Interrupts are chained from underlying MSI-X vectors.  We have
 * these irq_chip functions to be able to handle level triggering
 * semantics and other acknowledgment tasks associated with the GPIO
 * mechanism.
 */
static struct irq_chip thunderx_gpio_irq_chip = {
	.name			= "GPIO",
	.irq_enable		= thunderx_gpio_irq_unmask,
	.irq_disable		= thunderx_gpio_irq_mask,
	.irq_ack		= thunderx_gpio_irq_ack,
	.irq_mask		= thunderx_gpio_irq_mask,
	.irq_mask_ack		= thunderx_gpio_irq_mask_ack,
	.irq_unmask		= thunderx_gpio_irq_unmask,
	.irq_set_type		= thunderx_gpio_irq_set_type,
	.irq_request_resources	= thunderx_gpio_irq_request_resources,
	.irq_release_resources	= thunderx_gpio_irq_release_resources,
	.flags			= IRQCHIP_SET_TYPE_MASKED
};

static int thunderx_gpio_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	void __iomem * const *tbl;
	struct device *dev = &pdev->dev;
	struct thunderx_gpio *gpio;
	struct gpio_chip *chip;
	int ngpio, i;
	int err = 0;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	raw_spin_lock_init(&gpio->lock);
	chip = &gpio->chip;

	pci_set_drvdata(pdev, gpio);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device: err %d\n", err);
		goto out;
	}

	err = pcim_iomap_regions(pdev, 1 << 0, KBUILD_MODNAME);
	if (err) {
		dev_err(dev, "Failed to iomap PCI device: err %d\n", err);
		goto out;
	}

	tbl = pcim_iomap_table(pdev);
	gpio->register_base = tbl[0];
	if (!gpio->register_base) {
		dev_err(dev, "Cannot map PCI resource\n");
		err = -ENOMEM;
		goto out;
	}

	if (pdev->subsystem_device == 0xa10a) {
		/* CN88XX has no GPIO_CONST register*/
		ngpio = 50;
		gpio->base_msi = 48;
	} else {
		u64 c = readq(gpio->register_base + GPIO_CONST);

		ngpio = c & GPIO_CONST_GPIOS_MASK;
		gpio->base_msi = (c >> 8) & 0xff;
	}

	gpio->msix_entries = devm_kzalloc(dev,
					  sizeof(struct msix_entry) * ngpio,
					  GFP_KERNEL);
	if (!gpio->msix_entries) {
		err = -ENOMEM;
		goto out;
	}

	gpio->irqdev_entries = devm_kzalloc(dev,
					    sizeof(struct thunderx_irqdev) * ngpio,
					    GFP_KERNEL);
	if (!gpio->irqdev_entries) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ngpio; i++)
		gpio->msix_entries[i].entry = gpio->base_msi + (2 * i);

	err = pci_enable_msix(pdev, gpio->msix_entries, ngpio);
	if (err < 0)
		goto out;

	chip->label = KBUILD_MODNAME;
	chip->parent = dev;
	chip->owner = THIS_MODULE;
	chip->base = -1; /* System allocated */
	chip->can_sleep = false;
	chip->ngpio = ngpio;
	chip->direction_input = thunderx_gpio_dir_in;
	chip->get = thunderx_gpio_get;
	chip->direction_output = thunderx_gpio_dir_out;
	chip->set = thunderx_gpio_set;
	chip->set_multiple = thunderx_gpio_set_multiple;
	chip->set_single_ended = thunderx_gpio_set_single_ended;
	err = gpiochip_add(chip);
	if (err)
		goto out;

	err = gpiochip_irqchip_add(chip, &thunderx_gpio_irq_chip, 0,
				   handle_level_irq, IRQ_TYPE_NONE);
	if (err) {
		dev_err(dev, "gpiochip_irqchip_add failed: %d\n", err);
		goto irqchip_out;
	}

	dev_info(dev, "ThunderX GPIO: %d lines with base %d.\n",
		 ngpio, chip->base);
	return 0;

irqchip_out:
	gpiochip_remove(chip);
out:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void thunderx_gpio_remove(struct pci_dev *pdev)
{
	struct thunderx_gpio *gpio = pci_get_drvdata(pdev);

	gpiochip_remove(&gpio->chip);
	pci_set_drvdata(pdev, NULL);
}

static const struct pci_device_id thunderx_gpio_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xA00A) },
	{ 0, }	/* end of table */
};

MODULE_DEVICE_TABLE(pci, thunderx_gpio_id_table);

static struct pci_driver thunderx_gpio_driver = {
	.name = KBUILD_MODNAME,
	.id_table = thunderx_gpio_id_table,
	.probe = thunderx_gpio_probe,
	.remove = thunderx_gpio_remove,
};

module_pci_driver(thunderx_gpio_driver);

MODULE_DESCRIPTION("Cavium Inc. ThunderX/OCTEON-TX GPIO Driver");
MODULE_LICENSE("GPL");
