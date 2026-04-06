// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/export.h>
#include <linux/memblock.h>
#include <linux/numa.h>

/* These are not inline because of header tangles. */
#ifdef CONFIG_CPUMASK_OFFSTACK
/**
 * alloc_cpumask_var_node - allocate a struct cpumask on a given node
 * @mask: pointer to cpumask_var_t where the cpumask is returned
 * @flags: GFP_ flags
 * @node: memory node from which to allocate or %NUMA_NO_NODE
 *
 * Only defined when CONFIG_CPUMASK_OFFSTACK=y, otherwise is
 * a nop returning a constant 1 (in <linux/cpumask.h>).
 *
 * Return: TRUE if memory allocation succeeded, FALSE otherwise.
 *
 * In addition, mask will be NULL if this fails.  Note that gcc is
 * usually smart enough to know that mask can never be NULL if
 * CONFIG_CPUMASK_OFFSTACK=n, so does code elimination in that case
 * too.
 */
bool alloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags, int node)
{
	*mask = kmalloc_node(cpumask_size(), flags, node);

#ifdef CONFIG_DEBUG_PER_CPU_MAPS
	if (!*mask) {
		printk(KERN_ERR "=> alloc_cpumask_var: failed!\n");
		dump_stack();
	}
#endif

	return *mask != NULL;
}
EXPORT_SYMBOL(alloc_cpumask_var_node);

/**
 * alloc_bootmem_cpumask_var - allocate a struct cpumask from the bootmem arena.
 * @mask: pointer to cpumask_var_t where the cpumask is returned
 *
 * Only defined when CONFIG_CPUMASK_OFFSTACK=y, otherwise is
 * a nop (in <linux/cpumask.h>).
 * Either returns an allocated (zero-filled) cpumask, or causes the
 * system to panic.
 */
void __init alloc_bootmem_cpumask_var(cpumask_var_t *mask)
{
	*mask = memblock_alloc_or_panic(cpumask_size(), SMP_CACHE_BYTES);
}

/**
 * free_cpumask_var - frees memory allocated for a struct cpumask.
 * @mask: cpumask to free
 *
 * This is safe on a NULL mask.
 */
void free_cpumask_var(cpumask_var_t mask)
{
	kfree(mask);
}
EXPORT_SYMBOL(free_cpumask_var);

/**
 * free_bootmem_cpumask_var - frees result of alloc_bootmem_cpumask_var
 * @mask: cpumask to free
 */
void __init free_bootmem_cpumask_var(cpumask_var_t mask)
{
	memblock_free(mask, cpumask_size());
}
#endif

/**
 * cpumask_local_spread - select the i'th cpu based on NUMA distances
 * @i: index number
 * @node: local numa_node
 *
 * Return: online CPU according to a numa aware policy; local cpus are returned
 * first, followed by non-local ones, then it wraps around.
 *
 * For those who wants to enumerate all CPUs based on their NUMA distances,
 * i.e. call this function in a loop, like:
 *
 * for (i = 0; i < num_online_cpus(); i++) {
 *	cpu = cpumask_local_spread(i, node);
 *	do_something(cpu);
 * }
 *
 * There's a better alternative based on for_each()-like iterators:
 *
 *	for_each_numa_hop_mask(mask, node) {
 *		for_each_cpu_andnot(cpu, mask, prev)
 *			do_something(cpu);
 *		prev = mask;
 *	}
 *
 * It's simpler and more verbose than above. Complexity of iterator-based
 * enumeration is O(sched_domains_numa_levels * nr_cpu_ids), while
 * cpumask_local_spread() when called for each cpu is
 * O(sched_domains_numa_levels * nr_cpu_ids * log(nr_cpu_ids)).
 */
unsigned int cpumask_local_spread(unsigned int i, int node)
{
	unsigned int cpu;

	/* Wrap: we always want a cpu. */
	i %= num_online_cpus();

	cpu = sched_numa_find_nth_cpu(cpu_online_mask, i, node);

	WARN_ON(cpu >= nr_cpu_ids);
	return cpu;
}
EXPORT_SYMBOL(cpumask_local_spread);

static DEFINE_PER_CPU(int, distribute_cpu_mask_prev);

/**
 * cpumask_any_and_distribute - Return an arbitrary cpu within src1p & src2p.
 * @src1p: first &cpumask for intersection
 * @src2p: second &cpumask for intersection
 *
 * Iterated calls using the same srcp1 and srcp2 will be distributed within
 * their intersection.
 *
 * Return: >= nr_cpu_ids if the intersection is empty.
 */
unsigned int cpumask_any_and_distribute(const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	unsigned int next, prev;

	/* NOTE: our first selection will skip 0. */
	prev = __this_cpu_read(distribute_cpu_mask_prev);

	next = cpumask_next_and_wrap(prev, src1p, src2p);
	if (next < nr_cpu_ids)
		__this_cpu_write(distribute_cpu_mask_prev, next);

	return next;
}
EXPORT_SYMBOL(cpumask_any_and_distribute);

/**
 * cpumask_any_distribute - Return an arbitrary cpu from srcp
 * @srcp: &cpumask for selection
 *
 * Return: >= nr_cpu_ids if the intersection is empty.
 */
unsigned int cpumask_any_distribute(const struct cpumask *srcp)
{
	unsigned int next, prev;

	/* NOTE: our first selection will skip 0. */
	prev = __this_cpu_read(distribute_cpu_mask_prev);
	next = cpumask_next_wrap(prev, srcp);
	if (next < nr_cpu_ids)
		__this_cpu_write(distribute_cpu_mask_prev, next);

	return next;
}
EXPORT_SYMBOL(cpumask_any_distribute);

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)	[x+1][0] = (1UL << (x))
#define MASK_DECLARE_2(x)	MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)	MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)	MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

	MASK_DECLARE_8(0),	MASK_DECLARE_8(8),
	MASK_DECLARE_8(16),	MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
	MASK_DECLARE_8(32),	MASK_DECLARE_8(40),
	MASK_DECLARE_8(48),	MASK_DECLARE_8(56),
#endif
};
EXPORT_SYMBOL_GPL(cpu_bit_bitmap);

const DECLARE_BITMAP(cpu_all_bits, NR_CPUS) = CPU_BITS_ALL;
EXPORT_SYMBOL(cpu_all_bits);

#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __ro_after_init
	= {CPU_BITS_ALL};
unsigned int __num_possible_cpus __ro_after_init = NR_CPUS;
#else
struct cpumask __cpu_possible_mask __ro_after_init;
unsigned int __num_possible_cpus __ro_after_init;
#endif
EXPORT_SYMBOL(__cpu_possible_mask);
EXPORT_SYMBOL(__num_possible_cpus);

struct cpumask __cpu_online_mask __read_mostly;
EXPORT_SYMBOL(__cpu_online_mask);

struct cpumask __cpu_enabled_mask __read_mostly;
EXPORT_SYMBOL(__cpu_enabled_mask);

struct cpumask __cpu_present_mask __read_mostly;
EXPORT_SYMBOL(__cpu_present_mask);

struct cpumask __cpu_active_mask __read_mostly;
EXPORT_SYMBOL(__cpu_active_mask);

struct cpumask __cpu_dying_mask __read_mostly;
EXPORT_SYMBOL(__cpu_dying_mask);

atomic_t __num_online_cpus __read_mostly;
EXPORT_SYMBOL(__num_online_cpus);

void init_cpu_present(const struct cpumask *src)
{
	cpumask_copy(&__cpu_present_mask, src);
}

void init_cpu_possible(const struct cpumask *src)
{
	cpumask_copy(&__cpu_possible_mask, src);
	__num_possible_cpus = cpumask_weight(&__cpu_possible_mask);
}

void set_cpu_online(unsigned int cpu, bool online)
{
	/*
	 * atomic_inc/dec() is required to handle the horrid abuse of this
	 * function by the reboot and kexec code which invoke it from
	 * IPI/NMI broadcasts when shutting down CPUs. Invocation from
	 * regular CPU hotplug is properly serialized.
	 *
	 * Note, that the fact that __num_online_cpus is of type atomic_t
	 * does not protect readers which are not serialized against
	 * concurrent hotplug operations.
	 */
	if (online) {
		if (!cpumask_test_and_set_cpu(cpu, &__cpu_online_mask))
			atomic_inc(&__num_online_cpus);
	} else {
		if (cpumask_test_and_clear_cpu(cpu, &__cpu_online_mask))
			atomic_dec(&__num_online_cpus);
	}
}

/*
 * This should be marked __init, but there is a boatload of call sites
 * which need to be fixed up to do so. Sigh...
 */
void set_cpu_possible(unsigned int cpu, bool possible)
{
	if (possible) {
		if (!cpumask_test_and_set_cpu(cpu, &__cpu_possible_mask))
			__num_possible_cpus++;
	} else {
		if (cpumask_test_and_clear_cpu(cpu, &__cpu_possible_mask))
			__num_possible_cpus--;
	}
}
