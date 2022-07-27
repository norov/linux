// SPDX-License-Identifier: GPL-2.0-or-later
/* Big-endian routines for bit search implementation */

#define word_op swab
#include "find_bit.h"

#ifndef find_first_zero_bit_le
/*
 * Find the first cleared bit in an LE memory region.
 */
unsigned long _find_first_zero_bit_le(const unsigned long *addr, unsigned long size)
{
	return FIND_FIRST_BIT(~addr[idx], nbits, 0);
}
EXPORT_SYMBOL(_find_first_zero_bit_le);

#ifndef find_next_zero_bit_le
unsigned long _find_next_zero_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return FIND_NEXT_BIT(~addr[idx], nbits, start);
}
#endif

#ifndef find_next_bit_le
unsigned long _find_next_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return FIND_NEXT_BIT(addr[idx], nbits, start);
}

#endif
