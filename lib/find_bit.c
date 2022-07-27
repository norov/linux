// SPDX-License-Identifier: GPL-2.0-or-later
/* bit search implementation
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Copyright (C) 2008 IBM Corporation
 * 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
 * size and improve performance, 2015.
 */

#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/swab.h>

#include "find_bit.h"

#ifndef find_first_bit
/*
 * Find the first set bit in a memory region.
 */
unsigned long _find_first_bit(const unsigned long *addr, unsigned long size)
{
	return FIND_FIRST_BIT(addr[idx], size);
}
EXPORT_SYMBOL(_find_first_bit);
#endif

#ifndef find_first_and_bit
/*
 * Find the first set bit in two memory regions.
 */
unsigned long _find_first_and_bit(const unsigned long *addr1,
				  const unsigned long *addr2,
				  unsigned long size)
{
	return FIND_FIRST_BIT(addr1[idx] & addr2[idx], size);
}
EXPORT_SYMBOL(_find_first_and_bit);
#endif

#ifndef find_first_zero_bit
/*
 * Find the first cleared bit in a memory region.
 */
unsigned long _find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	return FIND_FIRST_BIT(~addr[idx], size);
}
EXPORT_SYMBOL(_find_first_zero_bit);
#endif

#ifndef find_next_bit
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	return FIND_NEXT_BIT(addr[idx], nbits, start);
}
EXPORT_SYMBOL(_find_next_bit);
#endif

#ifndef find_next_and_bit
unsigned long _find_next_and_bit(const unsigned long *addr1, const unsigned long *addr2,
					unsigned long nbits, unsigned long start)
{
	return FIND_NEXT_BIT(addr1[idx] & addr2[idx], nbits, start);
}
EXPORT_SYMBOL(_find_next_and_bit);
#endif

#ifndef find_next_zero_bit
unsigned long _find_next_zero_bit(const unsigned long *addr, unsigned long nbits,
					 unsigned long start)
{
	return FIND_NEXT_BIT(~addr[idx], nbits, start);
}
EXPORT_SYMBOL(_find_next_zero_bit);
#endif

#ifndef find_last_bit
unsigned long _find_last_bit(const unsigned long *addr, unsigned long size)
{
	if (size) {
		unsigned long val = BITMAP_LAST_WORD_MASK(size);
		unsigned long idx = (size-1) / BITS_PER_LONG;

		do {
			val &= addr[idx];
			if (val)
				return idx * BITS_PER_LONG + __fls(val);

			val = ~0ul;
		} while (idx--);
	}
	return size;
}
EXPORT_SYMBOL(_find_last_bit);
#endif

unsigned long find_next_clump8(unsigned long *clump, const unsigned long *addr,
			       unsigned long size, unsigned long offset)
{
	offset = find_next_bit(addr, size, offset);
	if (offset == size)
		return size;

	offset = round_down(offset, 8);
	*clump = bitmap_get_value8(addr, offset);

	return offset;
}
EXPORT_SYMBOL(find_next_clump8);
