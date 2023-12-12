/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CPUMASK_ATOMIC_H_
#define __LINUX_CPUMASK_ATOMIC_H_

#include <linux/cpumask.h>
#include <linux/find_atomic.h>

/*
 * cpumask_find_and_set - find the first unset cpu in a cpumask and
 *			  set it atomically
 * @srcp: the cpumask pointer
 *
 * Return: >= nr_cpu_ids if nothing is found.
 */
static inline unsigned int cpumask_find_and_set(volatile struct cpumask *srcp)
{
	return find_and_set_bit(cpumask_bits(srcp), small_cpumask_bits);
}

#endif /* __LINUX_CPUMASK_ATOMIC_H_ */
