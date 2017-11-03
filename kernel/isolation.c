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
#include <linux/smp.h>
#include <linux/tick.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include "time/tick-sched.h"

/*
 * These values are stored in task_isolation_state.
 * Note that STATE_NORMAL + TIF_TASK_ISOLATION means we are still
 * returning from sys_prctl() to userspace.
 */
enum {
	STATE_NORMAL = 0,	/* Not isolated */
	STATE_ISOLATED = 1,	/* In userspace, isolated */
	STATE_WARNED = 2	/* Like ISOLATED but console warning issued */
};

cpumask_var_t task_isolation_map;

/* We can run on cpus that are isolated from the scheduler and are nohz_full. */
static int __init task_isolation_init(void)
{
	if (alloc_cpumask_var(&task_isolation_map, GFP_KERNEL))
		cpumask_and(task_isolation_map, cpu_isolated_map,
			    tick_nohz_full_mask);

	return 0;
}
core_initcall(task_isolation_init)

static inline bool is_isolation_cpu(int cpu)
{
	return task_isolation_map != NULL &&
		cpumask_test_cpu(cpu, task_isolation_map);
}

/* Enable stack backtraces of any interrupts of task_isolation cores. */
static bool task_isolation_debug;
static int __init task_isolation_debug_func(char *str)
{
	task_isolation_debug = true;
	return 1;
}
__setup("task_isolation_debug", task_isolation_debug_func);

/*
 * Dump stack if need be. This can be helpful even from the final exit
 * to usermode code since stack traces sometimes carry information about
 * what put you into the kernel, e.g. an interrupt number encoded in
 * the initial entry stack frame that is still visible at exit time.
 */
static void debug_dump_stack(void)
{
	if (task_isolation_debug)
		dump_stack();
}

/*
 * Set the flags word but don't try to actually start task isolation yet.
 * We will start it when entering user space in task_isolation_start().
 */
int task_isolation_request(unsigned int flags)
{
	struct task_struct *task = current;

	/*
	 * The task isolation flags should always be cleared just by
	 * virtue of having entered the kernel.
	 */
	WARN_ON_ONCE(test_tsk_thread_flag(task, TIF_TASK_ISOLATION));
	WARN_ON_ONCE(task->task_isolation_flags != 0);
	WARN_ON_ONCE(task->task_isolation_state != STATE_NORMAL);

	task->task_isolation_flags = flags;
	if (!(task->task_isolation_flags & PR_TASK_ISOLATION_ENABLE))
		return 0;

	/* We are trying to enable task isolation. */
	set_tsk_thread_flag(task, TIF_TASK_ISOLATION);

	/*
	 * Shut down the vmstat worker so we're not interrupted later.
	 * We have to try to do this here (with interrupts enabled) since
	 * we are canceling delayed work and will call flush_work()
	 * (which enables interrupts) and possibly schedule().
	 */
	quiet_vmstat_sync();

	/* We return 0 here but we may change that in task_isolation_start(). */
	return 0;
}

/* Disable task isolation in the specified task. */
static void stop_isolation(struct task_struct *p)
{
	p->task_isolation_flags = 0;
	p->task_isolation_state = STATE_NORMAL;
	clear_tsk_thread_flag(p, TIF_TASK_ISOLATION);
}

/*
 * This code runs with interrupts disabled just before the return to
 * userspace, after a prctl() has requested enabling task isolation.
 * We take whatever steps are needed to avoid being interrupted later:
 * drain the lru pages, stop the scheduler tick, etc.  More
 * functionality may be added here later to avoid other types of
 * interrupts from other kernel subsystems.
 *
 * If we can't enable task isolation, we update the syscall return
 * value with an appropriate error.
 */
void task_isolation_start(void)
{
	int error;

	/*
	 * We should only be called in STATE_NORMAL (isolation disabled),
	 * on our way out of the kernel from the prctl() that turned it on.
	 * If we are exiting from the kernel in another state, it means we
	 * made it back into the kernel without disabling task isolation,
	 * and we should investigate how (and in any case disable task
	 * isolation at this point).  We are clearly not on the path back
	 * from the prctl() so we don't touch the syscall return value.
	 */
	if (WARN_ON_ONCE(current->task_isolation_state != STATE_NORMAL)) {
		stop_isolation(current);
		return;
	}

	/*
	 * Must be affinitized to a single core with task isolation possible.
	 * In principle this could be remotely modified between the prctl()
	 * and the return to userspace, so we have to check it here.
	 */
	if (cpumask_weight(&current->cpus_allowed) != 1 ||
	    !is_isolation_cpu(smp_processor_id())) {
		error = -EINVAL;
		goto error;
	}

	/* If the vmstat delayed work is not canceled, we have to try again. */
	if (!vmstat_idle()) {
		error = -EAGAIN;
		goto error;
	}

	/* Try to stop the dynamic tick. */
	error = try_stop_full_tick();
	if (error)
		goto error;

	/* Drain the pagevecs to avoid unnecessary IPI flushes later. */
	lru_add_drain();

	current->task_isolation_state = STATE_ISOLATED;
	return;

error:
	stop_isolation(current);
	syscall_set_return_value(current, current_pt_regs(), error, 0);
}

/* Stop task isolation on the remote task and send it a signal. */
static void send_isolation_signal(struct task_struct *task)
{
	int flags = task->task_isolation_flags;
	siginfo_t info = {
		.si_signo = PR_TASK_ISOLATION_GET_SIG(flags) ?: SIGKILL,
	};

	stop_isolation(task);
	send_sig_info(info.si_signo, &info, task);
}

/* Only a few syscalls are valid once we are in task isolation mode. */
static bool is_acceptable_syscall(int syscall)
{
	/* No need to incur an isolation signal if we are just exiting. */
	if (syscall == __NR_exit || syscall == __NR_exit_group)
		return true;

	/* Check to see if it's the prctl for isolation. */
	if (syscall == __NR_prctl) {
		unsigned long arg;

		syscall_get_arguments(current, current_pt_regs(), 0, 1, &arg);
		if (arg == PR_TASK_ISOLATION)
			return true;
	}

	return false;
}

/*
 * This routine is called from syscall entry, prevents most syscalls
 * from executing, and if needed raises a signal to notify the process.
 *
 * Note that we have to stop isolation before we even print a message
 * here, since otherwise we might end up reporting an interrupt due to
 * kicking the printk handling code, rather than reporting the true
 * cause of interrupt here.
 */
int task_isolation_syscall(int syscall)
{
	struct task_struct *task = current;

	if (is_acceptable_syscall(syscall)) {
		stop_isolation(task);
		return 0;
	}

	send_isolation_signal(task);

	pr_warn("%s/%d (cpu %d): task_isolation lost due to syscall %d\n",
		task->comm, task->pid, smp_processor_id(), syscall);
	debug_dump_stack();

	syscall_set_return_value(task, current_pt_regs(), -ERESTARTNOINTR, -1);
	return -1;
}

/*
 * This routine is called from any exception or irq that doesn't
 * otherwise trigger a signal to the user process (e.g. page fault).
 * We don't warn if we are in STATE_WARNED in case a remote cpu already
 * reported that it was going to interrupt us, so we don't generate
 * a lot of confusingly similar messages about the same event.
 */
void _task_isolation_interrupt(const char *fmt, ...)
{
	struct task_struct *task = current;
	va_list args;
	char buf[100];
	bool do_warn;

	/* RCU should have been enabled prior to this point. */
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "kernel entry without RCU");

	/*
	 * Avoid reporting interrupts that happen after we have prctl'ed
	 * to enable isolation, but before we have returned to userspace.
	 */
	if (task->task_isolation_state == STATE_NORMAL)
		return;

	do_warn = (task->task_isolation_state == STATE_ISOLATED);

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/* Handle NMIs minimally, since we can't send a signal. */
	if (in_nmi()) {
		pr_err("%s/%d (cpu %d): in NMI; not delivering signal\n",
			task->comm, task->pid, smp_processor_id());
	} else {
		send_isolation_signal(task);
	}

	if (do_warn) {
		pr_warn("%s/%d (cpu %d): task_isolation lost due to %s\n",
			task->comm, task->pid, smp_processor_id(), buf);
		debug_dump_stack();
	}
}

/*
 * Called before we wake up a task that has a signal to process.
 * Needs to be done to handle interrupts that trigger signals, which
 * we don't catch with task_isolation_interrupt() hooks.
 */
void _task_isolation_signal(struct task_struct *task)
{
	bool do_warn = (task->task_isolation_state == STATE_ISOLATED);

	stop_isolation(task);
	if (do_warn) {
		pr_warn("%s/%d (cpu %d): task_isolation lost due to signal\n",
			task->comm, task->pid, task_cpu(task));
		debug_dump_stack();
	}
}

/*
 * Return a task_struct pointer (with ref count bumped up) for the
 * specified cpu if the task running on that cpu at this moment is in
 * isolation mode and hasn't yet been warned, otherwise NULL.
 * In addition, toggle the task state to WARNED in anticipation of
 * doing a printk, and send a reschedule IPI if needed.
 */
static struct task_struct *isolation_task(int cpu, int do_interrupt)
{
	struct task_struct *p = try_get_task_struct_on_cpu(cpu);

	if (p == NULL)
		return NULL;

	if (p->task_isolation_state != STATE_ISOLATED)
		goto bad_task;

	/*
	 * If we are claiming to be delivering a remote interrupt to our
	 * own task, this has to be a bug, since here we are already in the
	 * kernel, and somehow we didn't reset to STATE_NORMAL.
	 */
	if (WARN_ON_ONCE(p == current)) {
		stop_isolation(p);
		goto bad_task;
	}

	p->task_isolation_state = STATE_WARNED;
	if (do_interrupt)
		smp_send_reschedule(cpu);

	return p;

bad_task:
	put_task_struct(p);
	return NULL;
}

/*
 * Generate a stack backtrace if we are going to interrupt another task
 * isolation process.
 */
void _task_isolation_remote(int cpu, bool do_interrupt, const char *fmt, ...)
{
	struct task_struct *p;
	va_list args;
	char buf[200];

	if (!is_isolation_cpu(cpu))
		return;

	p = isolation_task(cpu, do_interrupt);
	if (p == NULL)
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	pr_warn("%s/%d (cpu %d): task_isolation lost due to %s by %s/%d on cpu %d\n",
		p->comm, p->pid, cpu, buf,
		current->comm, current->pid, smp_processor_id());
	put_task_struct(p);
	debug_dump_stack();
}

/*
 * Generate a stack backtrace if any of the cpus in "mask" are running
 * task isolation processes.
 */
void _task_isolation_remote_cpumask(const struct cpumask *mask,
				    bool do_interrupt, const char *fmt, ...)
{
	struct task_struct *p = NULL;
	cpumask_var_t warn_mask;
	va_list args;
	char buf[200];
	int cpu;

	if (task_isolation_map == NULL ||
	    !zalloc_cpumask_var(&warn_mask, GFP_KERNEL))
		return;

	for_each_cpu_and(cpu, mask, task_isolation_map) {
		if (p)
			put_task_struct(p);
		p = isolation_task(cpu, do_interrupt);
		if (p)
			cpumask_set_cpu(cpu, warn_mask);
	}
	if (p == NULL)
		goto done;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	pr_warn("%s/%d %s %*pbl): task_isolation lost due to %s by %s/%d on cpu %d\n",
		p->comm, p->pid,
		cpumask_weight(warn_mask) == 1 ? "(cpu" : "etc (cpus",
		cpumask_pr_args(warn_mask), buf,
		current->comm, current->pid, smp_processor_id());
	put_task_struct(p);
	debug_dump_stack();

done:
	free_cpumask_var(warn_mask);
}
