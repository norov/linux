/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_FIND_ATOMIC_H_
#define __LINUX_FIND_ATOMIC_H_

#include <linux/bitops.h>

unsigned long _find_and_set_bit(volatile unsigned long *addr, unsigned long nbits);
unsigned long _find_and_set_next_bit(volatile unsigned long *addr, unsigned long nbits,
				unsigned long start);
unsigned long _find_and_set_bit_lock(volatile unsigned long *addr, unsigned long nbits);
unsigned long _find_and_set_next_bit_lock(volatile unsigned long *addr, unsigned long nbits,
					  unsigned long start);
unsigned long _find_and_clear_bit(volatile unsigned long *addr, unsigned long nbits);
unsigned long _find_and_clear_next_bit(volatile unsigned long *addr, unsigned long nbits,
				unsigned long start);

/**
 * find_and_set_bit - Find a zero bit and set it atomically
 * @addr: The address to base the search on
 * @nbits: The bitmap size in bits
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the bitmap. It's also not
 * guaranteed that if @nbits is returned, the bitmap is empty.
 *
 * The function does guarantee that if returned value is in range [0 .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and set bit, or @nbits if no bits found
 */
static inline
unsigned long find_and_set_bit(volatile unsigned long *addr, unsigned long nbits)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr | ~GENMASK(nbits - 1, 0);
			if (val == ~0UL)
				return nbits;
			ret = ffz(val);
		} while (test_and_set_bit(ret, addr));

		return ret;
	}

	return _find_and_set_bit(addr, nbits);
}


/**
 * find_and_set_next_bit - Find a zero bit and set it, starting from @offset
 * @addr: The address to base the search on
 * @nbits: The bitmap nbits in bits
 * @offset: The bitnumber to start searching at
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the bitmap, starting from @offset.
 * It's also not guaranteed that if @nbits is returned, the bitmap is empty.
 *
 * The function does guarantee that if returned value is in range [@offset .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and set bit, or @nbits if no bits found
 */
static inline
unsigned long find_and_set_next_bit(volatile unsigned long *addr,
				    unsigned long nbits, unsigned long offset)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr | ~GENMASK(nbits - 1, offset);
			if (val == ~0UL)
				return nbits;
			ret = ffz(val);
		} while (test_and_set_bit(ret, addr));

		return ret;
	}

	return _find_and_set_next_bit(addr, nbits, offset);
}

/**
 * find_and_set_bit_wrap - find and set bit starting at @offset, wrapping around zero
 * @addr: The first address to base the search on
 * @nbits: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * Returns: the bit number for the next clear bit, or first clear bit up to @offset,
 * while atomically setting it. If no bits are found, returns @nbits.
 */
static inline
unsigned long find_and_set_bit_wrap(volatile unsigned long *addr,
					unsigned long nbits, unsigned long offset)
{
	unsigned long bit = find_and_set_next_bit(addr, nbits, offset);

	if (bit < nbits || offset == 0)
		return bit;

	bit = find_and_set_bit(addr, offset);
	return bit < offset ? bit : nbits;
}

/**
 * find_and_set_bit_lock - find a zero bit, then set it atomically with lock
 * @addr: The address to base the search on
 * @nbits: The bitmap nbits in bits
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the bitmap. It's also not
 * guaranteed that if @nbits is returned, the bitmap is empty.
 *
 * The function does guarantee that if returned value is in range [0 .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and set bit, or @nbits if no bits found
 */
static inline
unsigned long find_and_set_bit_lock(volatile unsigned long *addr, unsigned long nbits)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr | ~GENMASK(nbits - 1, 0);
			if (val == ~0UL)
				return nbits;
			ret = ffz(val);
		} while (test_and_set_bit_lock(ret, addr));

		return ret;
	}

	return _find_and_set_bit_lock(addr, nbits);
}

/**
 * find_and_set_next_bit_lock - find a zero bit and set it atomically with lock
 * @addr: The address to base the search on
 * @nbits: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the range. It's also not
 * guaranteed that if @nbits is returned, the bitmap is empty.
 *
 * The function does guarantee that if returned value is in range [@offset .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and set bit, or @nbits if no bits found
 */
static inline
unsigned long find_and_set_next_bit_lock(volatile unsigned long *addr,
					 unsigned long nbits, unsigned long offset)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr | ~GENMASK(nbits - 1, offset);
			if (val == ~0UL)
				return nbits;
			ret = ffz(val);
		} while (test_and_set_bit_lock(ret, addr));

		return ret;
	}

	return _find_and_set_next_bit_lock(addr, nbits, offset);
}

/**
 * find_and_set_bit_wrap_lock - find zero bit starting at @ofset and set it
 *				with lock, and wrap around zero if nothing found
 * @addr: The first address to base the search on
 * @nbits: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * Returns: the bit number for the next set bit, or first set bit up to @offset
 * If no bits are set, returns @nbits.
 */
static inline
unsigned long find_and_set_bit_wrap_lock(volatile unsigned long *addr,
					unsigned long nbits, unsigned long offset)
{
	unsigned long bit = find_and_set_next_bit_lock(addr, nbits, offset);

	if (bit < nbits || offset == 0)
		return bit;

	bit = find_and_set_bit_lock(addr, offset);
	return bit < offset ? bit : nbits;
}

/**
 * find_and_clear_bit - Find a set bit and clear it atomically
 * @addr: The address to base the search on
 * @nbits: The bitmap nbits in bits
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the bitmap. It's also not
 * guaranteed that if @nbits is returned, the bitmap is empty.
 *
 * The function does guarantee that if returned value is in range [0 .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and cleared bit, or @nbits if no bits found
 */
static inline unsigned long find_and_clear_bit(volatile unsigned long *addr, unsigned long nbits)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr & GENMASK(nbits - 1, 0);
			if (val == 0)
				return nbits;
			ret = __ffs(val);
		} while (!test_and_clear_bit(ret, addr));

		return ret;
	}

	return _find_and_clear_bit(addr, nbits);
}

/**
 * find_and_clear_next_bit - Find a set bit next after @offset, and clear it atomically
 * @addr: The address to base the search on
 * @nbits: The bitmap nbits in bits
 * @offset: bit offset at which to start searching
 *
 * This function is designed to operate in concurrent access environment.
 *
 * Because of concurrency and volatile nature of underlying bitmap, it's not
 * guaranteed that the found bit is the 1st bit in the range It's also not
 * guaranteed that if @nbits is returned, there's no set bits after @offset.
 *
 * The function does guarantee that if returned value is in range [@offset .. @nbits),
 * the acquired bit belongs to the caller exclusively.
 *
 * Returns: found and cleared bit, or @nbits if no bits found
 */
static inline
unsigned long find_and_clear_next_bit(volatile unsigned long *addr,
					unsigned long nbits, unsigned long offset)
{
	if (small_const_nbits(nbits)) {
		unsigned long val, ret;

		do {
			val = *addr & GENMASK(nbits - 1, offset);
			if (val == 0)
				return nbits;
			ret = __ffs(val);
		} while (!test_and_clear_bit(ret, addr));

		return ret;
	}

	return _find_and_clear_next_bit(addr, nbits, offset);
}

/**
 * __find_and_set_bit - Find a zero bit and set it non-atomically
 * @addr: The address to base the search on
 * @nbits: The bitmap size in bits
 *
 * A non-atomic version of find_and_set_bit() needed to help writing
 * common-looking code where atomicity is provided externally.
 *
 * Returns: found and set bit, or @nbits if no bits found
 */
static inline
unsigned long __find_and_set_bit(unsigned long *addr, unsigned long nbits)
{
	unsigned long bit;

	bit = find_first_zero_bit(addr, nbits);
	if (bit < nbits)
		__set_bit(bit, addr);

	return bit;
}

/* same as for_each_set_bit() but atomically clears each found bit */
#define for_each_test_and_clear_bit(bit, addr, size) \
	for ((bit) = 0; \
	     (bit) = find_and_clear_next_bit((addr), (size), (bit)), (bit) < (size); \
	     (bit)++)

/* same as for_each_set_bit_from() but atomically clears each found bit */
#define for_each_test_and_clear_bit_from(bit, addr, size) \
	for (; (bit) = find_and_clear_next_bit((addr), (size), (bit)), (bit) < (size); (bit)++)

/* same as for_each_clear_bit() but atomically sets each found bit */
#define for_each_test_and_set_bit(bit, addr, size) \
	for ((bit) = 0; \
	     (bit) = find_and_set_next_bit((addr), (size), (bit)), (bit) < (size); \
	     (bit)++)

/* same as for_each_clear_bit_from() but atomically clears each found bit */
#define for_each_test_and_set_bit_from(bit, addr, size) \
	for (; \
	     (bit) = find_and_set_next_bit((addr), (size), (bit)), (bit) < (size); \
	     (bit)++)

#endif /* __LINUX_FIND_ATOMIC_H_ */
