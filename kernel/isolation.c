/*
 *  linux/kernel/isolation.c
 *
 *  Implementation for task isolation.
 *
 *  Distributed under GPLv2.
 */

#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/isolation.h>
#include <linux/syscalls.h>
#include <linux/ratelimit.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include "time/tick-sched.h"

cpumask_var_t task_isolation_map;
static bool saw_boot_arg;

/*
 * Isolation requires both nohz and isolcpus support from the scheduler.
 * We provide a boot flag that enables both for now, and which we can
 * add other functionality to over time if needed.  Note that just
 * specifying "nohz_full=... isolcpus=..." does not enable task isolation.
 */
static int __init task_isolation_setup(char *str)
{
	saw_boot_arg = true;

	alloc_bootmem_cpumask_var(&task_isolation_map);
	if (cpulist_parse(str, task_isolation_map) < 0) {
		pr_warn("task_isolation: Incorrect cpumask '%s'\n", str);
		return 1;
	}

	return 1;
}
__setup("task_isolation=", task_isolation_setup);

int __init task_isolation_init(void)
{
	/* For offstack cpumask, ensure we allocate an empty cpumask early. */
	if (!saw_boot_arg) {
#ifdef CONFIG_TASK_ISOLATION_ALL
		alloc_cpumask_var(&task_isolation_map, GFP_KERNEL);
		cpumask_copy(task_isolation_map, cpu_possible_mask);
		cpumask_clear_cpu(smp_processor_id(), task_isolation_map);
#else
		zalloc_cpumask_var(&task_isolation_map, GFP_KERNEL);
		return 0;
#endif
	}

	/*
	 * Add our task_isolation cpus to nohz_full and isolcpus.  Note
	 * that we are called relatively early in boot, from tick_init();
	 * at this point neither nohz_full nor isolcpus has been used
	 * to configure the system, but isolcpus has been allocated
	 * already in sched_init().
	 */
	tick_nohz_full_add_cpus(task_isolation_map);
	cpumask_or(cpu_isolated_map, cpu_isolated_map, task_isolation_map);

	return 0;
}

/*
 * Get a snapshot of whether, at this moment, it would be possible to
 * stop the tick.  This test normally requires interrupts disabled since
 * the condition can change if an interrupt is delivered.  However, in
 * this case we are using it in an advisory capacity to see if there
 * is anything obviously indicating that the task isolation
 * preconditions have not been met, so it's OK that in principle it
 * might not still be true later in the prctl() syscall path.
 */
static bool can_stop_my_full_tick_now(void)
{
	bool ret;

	local_irq_disable();
	ret = can_stop_my_full_tick();
	local_irq_enable();
	return ret;
}

/* Get the signal number that will be sent for a particular set of flag bits. */
static int task_isolation_sig(int flags)
{
	if (flags & PR_TASK_ISOLATION_USERSIG)
		return PR_TASK_ISOLATION_GET_SIG(flags);
	else
		return SIGKILL;
}

/*
 * This routine controls whether we can enable task-isolation mode.
 * The task must be affinitized to a single task_isolation core, or
 * else we return EINVAL.  And, it must be at least statically able to
 * stop the nohz_full tick (e.g., no other schedulable tasks currently
 * running, no POSIX cpu timers currently set up, etc.); if not, we
 * return EAGAIN.
 *
 * If we will not be strictly enforcing kernel re-entry with a signal,
 * we just generate a warning printk if there is a bad affinity set
 * on entry (since after all you can always change it again after you
 * call prctl) and we don't bother failing the prctl with -EAGAIN
 * since we assume you will go in and out of kernel mode anyway.
 */
int task_isolation_set(unsigned int flags)
{
	if (flags != 0) {
		int sig = task_isolation_sig(flags);

		if (cpumask_weight(tsk_cpus_allowed(current)) != 1 ||
		    !task_isolation_possible(raw_smp_processor_id())) {
			/* Invalid task affinity setting. */
			if (sig)
				return -EINVAL;
			pr_warn("%s/%d: enabling non-signalling task isolation\n"
			"and not bound to a single task isolation core\n",
			current->comm, current->pid);
		}

		if (sig && !can_stop_my_full_tick_now()) {
			/* System not yet ready for task isolation. */
			return -EAGAIN;
		}
	}

	task_isolation_set_flags(current, flags);
	return 0;
}

/*
 * In task isolation mode we try to return to userspace only after
 * attempting to make sure we won't be interrupted again.  This test
 * is run with interrupts disabled to test that everything we need
 * to be true is true before we can return to userspace.
 */
bool task_isolation_ready(void)
{
	WARN_ON_ONCE(!irqs_disabled());

	return (!lru_add_drain_needed(smp_processor_id()) &&
		vmstat_idle() &&
		tick_nohz_tick_stopped());
}

/*
 * Each time we try to prepare for return to userspace in a process
 * with task isolation enabled, we run this code to quiesce whatever
 * subsystems we can readily quiesce to avoid later interrupts.
 */
void task_isolation_enter(void)
{
	WARN_ON_ONCE(irqs_disabled());

	/* Drain the pagevecs to avoid unnecessary IPI flushes later. */
	lru_add_drain();

	/* Quieten the vmstat worker so it won't interrupt us. */
	if (!vmstat_idle())
		quiet_vmstat_sync();

	/*
	 * Request rescheduling unless we are in full dynticks mode.
	 * We would eventually get pre-empted without this, and if
	 * there's another task waiting, it would run; but by
	 * explicitly requesting the reschedule, we may reduce the
	 * latency.  We could directly call schedule() here as well,
	 * but since our caller is the standard place where schedule()
	 * is called, we defer to the caller.
	 *
	 * A more substantive approach here would be to use a struct
	 * completion here explicitly, and complete it when we shut
	 * down dynticks, but since we presumably have nothing better
	 * to do on this core anyway, just spinning seems plausible.
	 */
	if (!tick_nohz_tick_stopped())
		set_tsk_need_resched(current);
}

static void task_isolation_deliver_signal(struct task_struct *task,
					  const char *buf, int sig)
{
	siginfo_t info = {};

	info.si_signo = sig;

	/*
	 * Report on the fact that isolation was violated for the task.
	 * It may not be the task's fault (e.g. a TLB flush from another
	 * core) but we are not blaming it, just reporting that it lost
	 * its isolation status.
	 */
	pr_warn("%s/%d: task_isolation mode lost due to %s\n",
		task->comm, task->pid, buf);

	/*
	 * Turn off task isolation mode to avoid further isolation callbacks.
	 * It can choose to re-enable task isolation mode in the signal handler.
	 */
	task_isolation_set_flags(task, 0);

	send_sig_info(info.si_signo, &info, task);
}

/*
 * This routine is called from any userspace exception that doesn't
 * otherwise trigger a signal to the user process (e.g. simple page fault).
 */
void _task_isolation_quiet_exception(const char *fmt, ...)
{
	struct task_struct *task = current;
	va_list args;
	char buf[100];
	int sig;

	/* RCU should have been enabled prior to this point. */
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "kernel entry without RCU");

	sig = task_isolation_sig(task->task_isolation_flags);
	if (sig == 0)
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	task_isolation_deliver_signal(task, buf, sig);
}

/*
 * This routine is called from syscall entry (with the syscall number
 * passed in), and prevents most syscalls from executing and raises a
 * signal to notify the process.
 */
int task_isolation_syscall(int syscall)
{
	char buf[20];
	int sig;

	if (syscall == __NR_prctl ||
	    syscall == __NR_exit ||
	    syscall == __NR_exit_group)
		return 0;

	sig = task_isolation_sig(current->task_isolation_flags);
	if (sig == 0)
		return 0;

	snprintf(buf, sizeof(buf), "syscall %d", syscall);
	task_isolation_deliver_signal(current, buf, sig);

	syscall_set_return_value(current, current_pt_regs(),
					 -ERESTARTNOINTR, -1);
	return -1;
}

/* Enable debugging of any interrupts of task_isolation cores. */
static int task_isolation_debug_flag;
static int __init task_isolation_debug_func(char *str)
{
	task_isolation_debug_flag = true;
	return 1;
}
__setup("task_isolation_debug", task_isolation_debug_func);

void task_isolation_debug_task(int cpu, struct task_struct *p, const char *type)
{
	static DEFINE_RATELIMIT_STATE(console_output, HZ, 1);
	bool force_debug = false;
	int sig;

	/*
	 * Our caller made sure the task was running on a task isolation
	 * core, but make sure the task has enabled isolation.
	 */
	if (!(p->task_isolation_flags & PR_TASK_ISOLATION_ENABLE))
		return;

	/*
	 * Ensure the task is actually in userspace; if it is in kernel
	 * mode, it is expected that it may receive interrupts, and in
	 * any case they don't affect the isolation.  Note that there
	 * is a race condition here as a task may have committed
	 * to returning to user space but not yet set the context
	 * tracking state to reflect it, and the check here is before
	 * we trigger the interrupt, so we might fail to warn about a
	 * legitimate interrupt.  However, the race window is narrow
	 * and hitting it does not cause any incorrect behavior other
	 * than failing to send the warning.
	 */
	if (cpu != smp_processor_id() && !context_tracking_cpu_in_user(cpu))
		return;

	/*
	 * We disable task isolation mode when we deliver a signal
	 * so we won't end up recursing back here again.
	 * If we are in an NMI, we don't try delivering the signal
	 * and instead just treat it as if "debug" mode was enabled,
	 * since that's pretty much all we can do.
	 */
	sig = task_isolation_sig(p->task_isolation_flags);
	if (sig != 0) {
		if (in_nmi())
			force_debug = true;
		else
			task_isolation_deliver_signal(p, type, sig);
	}

	/*
	 * If (for example) the timer interrupt starts ticking
	 * unexpectedly, we will get an unmanageable flow of output,
	 * so limit to one backtrace per second.
	 */
	if (force_debug ||
	    (task_isolation_debug_flag && __ratelimit(&console_output))) {
		pr_err("cpu %d: %s violating task isolation for %s/%d on cpu %d\n",
		       smp_processor_id(), type, p->comm, p->pid, cpu);
		dump_stack();
	}
}

void task_isolation_debug_cpumask(const struct cpumask *mask, const char *type)
{
	int cpu, thiscpu = get_cpu();

	/* No need to report on this cpu since we're already in the kernel. */
	for_each_cpu_and(cpu, mask, task_isolation_map)
		if (cpu != thiscpu)
			_task_isolation_debug(cpu, type);

	put_cpu();
}

extern struct task_struct *curr_task(int cpu);

int task_isolation_on_cpu(int cpu)
{
	struct task_struct *tsk = curr_task(cpu);

	return tsk != NULL && test_tsk_thread_flag(tsk, TIF_TASK_ISOLATION);
}

void task_isolation_cpumask(struct cpumask *mask)
{
	int cpu;

	if (task_isolation_map == NULL)
		return;

	/* No need to report on this cpu since we're already in the kernel. */
	for_each_cpu(cpu, task_isolation_map)
		if (task_isolation_on_cpu(cpu))
			cpumask_set_cpu(cpu, mask);
}
