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
#endif
