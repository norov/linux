/*
 * simple parameterized no-irq of_driven i2c->gpio expander,
 * cut down from gpio-pcf857x.c to be totally device-tree driven.
 *
 * Suitable for any "memory-like" device, where a 1-byte i2c read yields data
 * which can safely be written back, possibly with a bit changed, with the
 * effect of changing only the output level of that bit's GPIO pin.
 *
 * Copyright (C) 2016 Cavium Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct gpio_i2c_platform_data {
	unsigned int	i2c_addr;
	unsigned int	pins;
};


static const struct of_device_id gpio_i2c_of_table[] = {
	{ .compatible = "gpio-i2c" },
	{ }
};
MODULE_DEVICE_TABLE(of, gpio_i2c_of_table);

struct gpio_i2c {
	unsigned int	i2c_addr;
	struct gpio_chip	chip;
	struct i2c_client	*client;
	struct mutex		lock;		/* protect 'out' */
	u8			out[];		/* software latch */
};

/*-------------------------------------------------------------------------*/

static int gpio_i2c_get(struct gpio_chip *chip, unsigned int offset)
{
	struct gpio_i2c	*gpio = container_of(chip, struct gpio_i2c, chip);
	int		value;
	unsigned int	byte = (offset >> 3);
	unsigned int	bit = (offset & 7);

	mutex_lock(&gpio->lock);
	value = i2c_smbus_read_byte_data(gpio->client, byte);
	mutex_unlock(&gpio->lock);
	return (value < 0) ? 0 : ((value >> bit) & 1);
}

static int gpio_i2c_output(struct gpio_chip *chip,
		unsigned int offset, int value)
{
	struct gpio_i2c	*gpio = container_of(chip, struct gpio_i2c, chip);
	unsigned int	byte = (offset >> 3);
	unsigned int	bit = (offset & 7);
	unsigned int	mask = (1 << bit);
	int		status;
	u8		was;

	mutex_lock(&gpio->lock);
	was = i2c_smbus_read_byte_data(gpio->client, byte);
	if (value)
		was |= mask;
	else
		was &= ~mask;
	status = i2c_smbus_write_byte_data(gpio->client, byte, was);
	gpio->out[byte] = was;
	mutex_unlock(&gpio->lock);

	return status;
}

static void gpio_i2c_set(struct gpio_chip *chip, unsigned int offset, int value)
{
	gpio_i2c_output(chip, offset, value);
}

/* for open-drain: set as input by letting output go high */
static int gpio_i2c_input(struct gpio_chip *chip, unsigned int offset)
{
	return gpio_i2c_output(chip, offset, 1);
}

/*-------------------------------------------------------------------------*/

static int gpio_i2c_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct gpio_i2c_platform_data	*pdata = dev_get_platdata(&client->dev);
	struct device_node		*np = client->dev.of_node;
	struct gpio_i2c			*gpio;
	u32				pins;
	u32				i2c_addr;
	int				status;

	if (np) {
		status = of_property_read_u32(np, "reg", &i2c_addr);
		if (status < 0) {
			dev_dbg(&client->dev, "missing reg property\n");
			return status;
		}
		status = of_property_read_u32(np, "ngpios", &pins);
		if (status < 0) {
			dev_dbg(&client->dev, "missing ngpios property\n");
			return status;
		}
	} else if (pdata) {
		i2c_addr = pdata->i2c_addr;
		pins = pdata->pins;
	} else {
		dev_dbg(&client->dev, "no platform data\n");
		return -EPROBE_DEFER;
	}

	/* Allocate, initialize, and register this gpio_chip. */
	gpio = devm_kzalloc(&client->dev,
		sizeof(*gpio) + (pins + 7) / 8, GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	mutex_init(&gpio->lock);

	gpio->i2c_addr			= i2c_addr;
	gpio->chip.base			= -1;
	gpio->chip.can_sleep		= true;
	gpio->chip.parent		= &client->dev;
	gpio->chip.owner		= THIS_MODULE;
	gpio->chip.get			= gpio_i2c_get;
	gpio->chip.set			= gpio_i2c_set;
	gpio->chip.direction_input	= gpio_i2c_input;
	gpio->chip.direction_output	= gpio_i2c_output;
	gpio->chip.ngpio		= pins;
	gpio->chip.label		= client->name;
	gpio->client			= client;
	gpio->client->addr		= i2c_addr;
	i2c_set_clientdata(client, gpio);

	status = gpiochip_add(&gpio->chip);
	if (status < 0)
		goto fail;

	dev_info(&client->dev, "probed\n");

	return 0;

fail:
	dev_dbg(&client->dev, "probe error %d for '%s'\n", status,
		client->name);

	return status;
}

static int gpio_i2c_remove(struct i2c_client *client)
{
	struct gpio_i2c			*gpio = i2c_get_clientdata(client);
	int				status = 0;

	gpiochip_remove(&gpio->chip);
	return status;
}

/* this must _exist_ for i2c_device_probe() to call our probe, may be empty */
static struct i2c_device_id empty_id_table[] = {
	{ },
};
MODULE_DEVICE_TABLE(i2c, empty_id_table);

static struct i2c_driver gpio_i2c_driver = {
	.driver = {
		.name	= "gpio-i2c",
		.of_match_table = of_match_ptr(gpio_i2c_of_table),
	},
	.probe	= gpio_i2c_probe,
	.remove	= gpio_i2c_remove,
	.id_table = empty_id_table,
};

module_i2c_driver(gpio_i2c_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Brownell");
MODULE_AUTHOR("Peter Swain <pswain@cavium.com>");
/*
 * arguably this name defies convention, but correct(?) alias has been
 * taken by the inverse function in
 *	drivers/i2c/busses/i2c-gpio.c:MODULE_ALIAS("platform:i2c-gpio");
 */
MODULE_ALIAS("platform:gpio-i2c");
