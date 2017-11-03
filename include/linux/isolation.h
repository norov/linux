/*
 * Task isolation related global functions
 */
#ifndef _LINUX_ISOLATION_H
#define _LINUX_ISOLATION_H

#include <stdarg.h>
#include <linux/errno.h>
#include <linux/cpumask.h>
#include <linux/prctl.h>
#include <linux/types.h>

struct task_struct;

#ifdef CONFIG_TASK_ISOLATION

/**
 * task_isolation_request() - prctl hook to request task isolation
 * @flags:	Flags from <linux/prctl.h> PR_TASK_ISOLATION_xxx.
 *
 * This is called from the generic prctl() code for PR_TASK_ISOLATION.

 * Return: Returns 0 when task isolation enabled, otherwise a negative
 * errno.
 */
extern int task_isolation_request(unsigned int flags);

/**
 * task_isolation_start() - attempt to actually start task isolation
 *
 * This function should be invoked as the last thing prior to returning to
 * user space if TIF_TASK_ISOLATION is set in the thread_info flags.  It
 * will attempt to quiesce the core and enter task-isolation mode.  If it
 * fails, it will reset the system call return value to an error code that
 * indicates the failure mode.
 */
extern void task_isolation_start(void);

/**
 * task_isolation_syscall() - report a syscall from an isolated task
 * @nr:		The syscall number.
 *
 * This routine should be invoked at syscall entry if TIF_TASK_ISOLATION is
 * set in the thread_info flags.  It checks for valid syscalls,
 * specifically prctl() with PR_TASK_ISOLATION, exit(), and exit_group().
 * For any other syscall it will raise a signal and return failure.
 *
 * Return: 0 for acceptable syscalls, -1 for all others.
 */
extern int task_isolation_syscall(int nr);

/**
 * _task_isolation_interrupt() - report an interrupt of an isolated task
 * @fmt:	A format string describing the interrupt
 * @...:	Format arguments, if any.
 *
 * This routine should be invoked at any exception or IRQ if
 * TIF_TASK_ISOLATION is set in the thread_info flags.  It is not necessary
 * to invoke it if the exception will generate a signal anyway (e.g. a bad
 * page fault), and in that case it is preferable not to invoke it but just
 * rely on the standard Linux signal.  The macro task_isolation_syscall()
 * wraps the TIF_TASK_ISOLATION flag test to simplify the caller code.
 */
extern void _task_isolation_interrupt(const char *fmt, ...);
#define task_isolation_interrupt(fmt, ...)				\
	do {								\
		if (current_thread_info()->flags & _TIF_TASK_ISOLATION) \
			_task_isolation_interrupt(fmt, ## __VA_ARGS__); \
	} while (0)

/**
 * _task_isolation_remote() - report a remote interrupt of an isolated task
 * @cpu:	The remote cpu that is about to be interrupted.
 * @do_interrupt: Whether we should generate an extra interrupt.
 * @fmt:	A format string describing the interrupt
 * @...:	Format arguments, if any.
 *
 * This routine should be invoked any time a remote IPI or other type of
 * interrupt is being delivered to another cpu.  The function will check to
 * see if the target core is running a task-isolation task, and generate a
 * diagnostic on the console if so; in addition, we tag the task so it
 * doesn't generate another diagnostic when the interrupt actually arrives.
 * Generating a diagnostic remotely yields a clearer indication of what
 * happened then just reporting only when the remote core is interrupted.
 *
 * The @do_interrupt flag, if true, causes the routine to not just print
 * the diagnostic, but also to generate a reschedule interrupt to the
 * remote core that is being interrupted.  This is necessary if the remote
 * interrupt being diagnosed will not otherwise be visible to the remote
 * core (e.g. a hypervisor service is being invoked on the remote core).
 * Sending a reschedule will force the core to trigger the isolation signal
 * and exit isolation mode.
 *
 * The task_isolation_remote() macro passes @do_interrupt as false, and the
 * task_isolation_remote_interrupt() passes the flag as true.
 */
extern void _task_isolation_remote(int cpu, bool do_interrupt,
				   const char *fmt, ...);
#define task_isolation_remote(cpu, fmt, ...) \
	_task_isolation_remote(cpu, false, fmt, ## __VA_ARGS__)
#define task_isolation_remote_interrupt(cpu, fmt, ...) \
	_task_isolation_remote(cpu, true, fmt, ## __VA_ARGS__)

/**
 * _task_isolation_remote_cpumask() - report interruption of multiple cpus
 * @mask:	The set of remotes cpus that are about to be interrupted.
 * @do_interrupt: Whether we should generate an extra interrupt.
 * @fmt:	A format string describing the interrupt
 * @...:	Format arguments, if any.
 *
 * This is the cpumask variant of _task_isolation_remote().  We
 * generate a single-line diagnostic message even if multiple remote
 * task-isolation cpus are being interrupted.
 */
extern void _task_isolation_remote_cpumask(const struct cpumask *mask,
					   bool do_interrupt,
					   const char *fmt, ...);
#define task_isolation_remote_cpumask(cpumask, fmt, ...) \
	_task_isolation_remote_cpumask(cpumask, false, fmt, ## __VA_ARGS__)
#define task_isolation_remote_cpumask_interrupt(cpumask, fmt, ...) \
	_task_isolation_remote_cpumask(cpumask, true, fmt, ## __VA_ARGS__)

/**
 * _task_isolation_signal() - disable task isolation when signal is pending
 * @task:	The task for which to disable isolation.
 *
 * This function generates a diagnostic and disables task isolation; it
 * should be called if TIF_TASK_ISOLATION is set when notifying a task of a
 * pending signal.  The task_isolation_interrupt() function normally
 * generates a diagnostic for events that just interrupt a task without
 * generating a signal; here we need to hook the paths that correspond to
 * interrupts that do generate a signal.  The macro task_isolation_signal()
 * wraps the TIF_TASK_ISOLATION flag test to simplify the caller code.
 */
extern void _task_isolation_signal(struct task_struct *task);
#define task_isolation_signal(task) do {				\
		if (task_thread_info(task)->flags & _TIF_TASK_ISOLATION) \
			_task_isolation_signal(task);			\
	} while (0)

/**
 * task_isolation_user_exit() - debug all user_exit calls
 *
 * By default, we don't generate an exception in the low-level user_exit()
 * code, because programs lose the ability to disable task isolation: the
 * user_exit() hook will cause a signal prior to task_isolation_syscall()
 * disabling task isolation.  In addition, it means that we lose all the
 * diagnostic info otherwise available from task_isolation_interrupt() hooks
 * later in the interrupt-handling process.  But you may enable it here for
 * a special kernel build if you are having undiagnosed userspace jitter.
 */
static inline void task_isolation_user_exit(void)
{
#ifdef DEBUG_TASK_ISOLATION
	task_isolation_interrupt("user_exit");
#endif
}

#else /* !CONFIG_TASK_ISOLATION */
static inline int task_isolation_request(unsigned int flags) { return -EINVAL; }
static inline void task_isolation_start(void) { }
static inline int task_isolation_syscall(int nr) { return 0; }
static inline void task_isolation_interrupt(const char *fmt, ...) { }
static inline void task_isolation_remote(int cpu, const char *fmt, ...) { }
static inline void task_isolation_remote_interrupt(int cpu,
						   const char *fmt, ...) { }
static inline void task_isolation_remote_cpumask(const struct cpumask *mask,
						 const char *fmt, ...) { }
static inline void task_isolation_remote_cpumask_interrupt(
	const struct cpumask *mask, const char *fmt, ...) { }
static inline void task_isolation_signal(struct task_struct *task) { }
static inline void task_isolation_user_exit(void) { }
#endif

#endif /* _LINUX_ISOLATION_H */
