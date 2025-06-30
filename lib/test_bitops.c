// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Intel Corporation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cleanup.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>

/* a tiny module only meant to test
 *
 *   set/clear_bit
 *   get_count_order/long
 */

/* use an enum because that's the most common BITMAP usage */
enum bitops_fun {
	BITOPS_4 = 4,
	BITOPS_7 = 7,
	BITOPS_11 = 11,
	BITOPS_31 = 31,
	BITOPS_88 = 88,
	BITOPS_LAST = 255,
	BITOPS_LENGTH = 256
};

static DECLARE_BITMAP(g_bitmap, BITOPS_LENGTH);

static unsigned int order_comb[][2] = {
	{0x00000003,  2},
	{0x00000004,  2},
	{0x00001fff, 13},
	{0x00002000, 13},
	{0x50000000, 31},
	{0x80000000, 31},
	{0x80003000, 32},
};

#ifdef CONFIG_64BIT
static unsigned long order_comb_long[][2] = {
	{0x0000000300000000, 34},
	{0x0000000400000000, 34},
	{0x00001fff00000000, 45},
	{0x0000200000000000, 45},
	{0x5000000000000000, 63},
	{0x8000000000000000, 63},
	{0x8000300000000000, 64},
};
#endif

static int __init test_fns(void)
{
	static volatile __always_used unsigned long tmp __initdata;
	unsigned long *buf __free(kfree) = NULL;
	unsigned int i, n;
	ktime_t time;

	buf = kmalloc_array(10000, sizeof(unsigned long), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	get_random_bytes(buf, 10000 * sizeof(unsigned long));
	time = ktime_get();

	for (n = 0; n < BITS_PER_LONG; n++)
		for (i = 0; i < 10000; i++)
			tmp = fns(buf[i], n);

	time = ktime_get() - time;
	pr_err("fns:  %18llu ns\n", time);

	return 0;
}

static void __init test_bitops_const_eval(void)
{
	/*
	 * ror/rol operations on parameters known at compile-time must be
	 * optimized to compile-time constants on any supported optimization
	 * level (-O2, -Os) and all architectures. Otherwise, trigger a build
	 * bug.
	 */

	u64 r64 = ror64(0x1234567890abcdefull, 24);

	BUILD_BUG_ON(!__builtin_constant_p(r64));
	BUILD_BUG_ON(r64 != 0xabcdef1234567890ull);

	u64 l64 = rol64(0x1234567890abcdefull, 24);

	BUILD_BUG_ON(!__builtin_constant_p(l64));
	BUILD_BUG_ON(l64 != 0x7890abcdef123456ull);

	u32 r32 = ror32(0x12345678, 24);

	BUILD_BUG_ON(!__builtin_constant_p(r32));
	BUILD_BUG_ON(r32 != 0x34567812);

	u32 l32 = rol32(0x12345678, 24);

	BUILD_BUG_ON(!__builtin_constant_p(l32));
	BUILD_BUG_ON(l32 != 0x78123456);

	u16 r16 = ror16(0x1234, 12);

	BUILD_BUG_ON(!__builtin_constant_p(r16));
	BUILD_BUG_ON(r16 != 0x2341);

	u16 l16 = rol16(0x1234, 12);

	BUILD_BUG_ON(!__builtin_constant_p(l16));
	BUILD_BUG_ON(l16 != 0x4123);

	u8 r8 = ror8(0x12, 6);

	BUILD_BUG_ON(!__builtin_constant_p(r16));
	BUILD_BUG_ON(r8 != 0x48);

	u8 l8 = rol8(0x12, 6);

	BUILD_BUG_ON(!__builtin_constant_p(l16));
	BUILD_BUG_ON(l8 != 0x84);
}

static int __init test_bitops_startup(void)
{
	int i, bit_set;

	pr_info("Starting bitops test\n");
	set_bit(BITOPS_4, g_bitmap);
	set_bit(BITOPS_7, g_bitmap);
	set_bit(BITOPS_11, g_bitmap);
	set_bit(BITOPS_31, g_bitmap);
	set_bit(BITOPS_88, g_bitmap);

	for (i = 0; i < ARRAY_SIZE(order_comb); i++) {
		if (order_comb[i][1] != get_count_order(order_comb[i][0]))
			pr_warn("get_count_order wrong for %x\n",
				       order_comb[i][0]);
	}

	for (i = 0; i < ARRAY_SIZE(order_comb); i++) {
		if (order_comb[i][1] != get_count_order_long(order_comb[i][0]))
			pr_warn("get_count_order_long wrong for %x\n",
				       order_comb[i][0]);
	}

#ifdef CONFIG_64BIT
	for (i = 0; i < ARRAY_SIZE(order_comb_long); i++) {
		if (order_comb_long[i][1] !=
			       get_count_order_long(order_comb_long[i][0]))
			pr_warn("get_count_order_long wrong for %lx\n",
				       order_comb_long[i][0]);
	}
#endif

	barrier();

	clear_bit(BITOPS_4, g_bitmap);
	clear_bit(BITOPS_7, g_bitmap);
	clear_bit(BITOPS_11, g_bitmap);
	clear_bit(BITOPS_31, g_bitmap);
	clear_bit(BITOPS_88, g_bitmap);

	bit_set = find_first_bit(g_bitmap, BITOPS_LAST);
	if (bit_set != BITOPS_LAST)
		pr_err("ERROR: FOUND SET BIT %d\n", bit_set);

	test_fns();
	test_bitops_const_eval();

	pr_info("Completed bitops test\n");

	return 0;
}

static void __exit test_bitops_unstartup(void)
{
}

module_init(test_bitops_startup);
module_exit(test_bitops_unstartup);

MODULE_AUTHOR("Jesse Brandeburg <jesse.brandeburg@intel.com>, Wei Yang <richard.weiyang@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bit testing module");
