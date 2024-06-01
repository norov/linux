/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CPUMASK_STR_H
#define __LINUX_CPUMASK_STR_H

#include <linux/cpumask_types.h>
#include <linux/bitmap-str.h>

/**
 * cpumask_parse_user - extract a cpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the cpumask to set.
 *
 * Return: -errno, or 0 for success.
 */
static inline int cpumask_parse_user(const char __user *buf, int len,
				     struct cpumask *dstp)
{
	return bitmap_parse_user(buf, len, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_parselist_user - extract a cpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the cpumask to set.
 *
 * Return: -errno, or 0 for success.
 */
static inline int cpumask_parselist_user(const char __user *buf, int len,
				     struct cpumask *dstp)
{
	return bitmap_parselist_user(buf, len, cpumask_bits(dstp),
				     nr_cpumask_bits);
}

/**
 * cpumask_parse - extract a cpumask from a string
 * @buf: the buffer to extract from
 * @dstp: the cpumask to set.
 *
 * Return: -errno, or 0 for success.
 */
static inline int cpumask_parse(const char *buf, struct cpumask *dstp)
{
	return bitmap_parse(buf, UINT_MAX, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpulist_parse - extract a cpumask from a user string of ranges
 * @buf: the buffer to extract from
 * @dstp: the cpumask to set.
 *
 * Return: -errno, or 0 for success.
 */
static inline int cpulist_parse(const char *buf, struct cpumask *dstp)
{
	return bitmap_parselist(buf, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumap_print_to_pagebuf  - copies the cpumask into the buffer either
 *	as comma-separated list of cpus or hex values of cpumask
 * @list: indicates whether the cpumap must be list
 * @mask: the cpumask to copy
 * @buf: the buffer to copy into
 *
 * Return: the length of the (null-terminated) @buf string, zero if
 * nothing is copied.
 */
static inline ssize_t
cpumap_print_to_pagebuf(bool list, char *buf, const struct cpumask *mask)
{
	return bitmap_print_to_pagebuf(list, buf, cpumask_bits(mask),
				      nr_cpu_ids);
}

/**
 * cpumap_print_bitmask_to_buf  - copies the cpumask into the buffer as
 *	hex values of cpumask
 *
 * @buf: the buffer to copy into
 * @mask: the cpumask to copy
 * @off: in the string from which we are copying, we copy to @buf
 * @count: the maximum number of bytes to print
 *
 * The function prints the cpumask into the buffer as hex values of
 * cpumask; Typically used by bin_attribute to export cpumask bitmask
 * ABI.
 *
 * Return: the length of how many bytes have been copied, excluding
 * terminating '\0'.
 */
static inline ssize_t
cpumap_print_bitmask_to_buf(char *buf, const struct cpumask *mask,
		loff_t off, size_t count)
{
	return bitmap_print_bitmask_to_buf(buf, cpumask_bits(mask),
				   nr_cpu_ids, off, count) - 1;
}

/**
 * cpumap_print_list_to_buf  - copies the cpumask into the buffer as
 *	comma-separated list of cpus
 * @buf: the buffer to copy into
 * @mask: the cpumask to copy
 * @off: in the string from which we are copying, we copy to @buf
 * @count: the maximum number of bytes to print
 *
 * Everything is same with the above cpumap_print_bitmask_to_buf()
 * except the print format.
 *
 * Return: the length of how many bytes have been copied, excluding
 * terminating '\0'.
 */
static inline ssize_t
cpumap_print_list_to_buf(char *buf, const struct cpumask *mask,
		loff_t off, size_t count)
{
	return bitmap_print_list_to_buf(buf, cpumask_bits(mask),
				   nr_cpu_ids, off, count) - 1;
}

#endif /* __LINUX_CPUMASK_STR_H */
