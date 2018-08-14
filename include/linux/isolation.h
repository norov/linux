/*
 * Task isolation related global functions
 */
#ifndef _LINUX_ISOLATION_H
#define _LINUX_ISOLATION_H

#include <linux/tick.h>
#include <linux/prctl.h>
#include <linux/hrtimer.h>

#ifdef CONFIG_TASK_ISOLATION

/* cpus that are configured to support task isolation */
extern cpumask_var_t task_isolation_map;

extern int task_isolation_init(void);

static inline bool task_isolation_possible(int cpu)
{
	return task_isolation_map != NULL &&
		cpumask_test_cpu(cpu, task_isolation_map);
}

extern int task_isolation_set(unsigned int flags);

extern bool task_isolation_ready(void);
extern void task_isolation_enter(void);

static inline void task_isolation_set_flags(struct task_struct *p,
					    unsigned int flags)
{
	p->task_isolation_flags = flags;

	if (flags & PR_TASK_ISOLATION_ENABLE)
		set_tsk_thread_flag(p, TIF_TASK_ISOLATION);
	else {
		clear_tsk_thread_flag(p, TIF_TASK_ISOLATION);

		/*
		 * We don't interrupt isolated task to update timer
		 * structures, so do on exit of isolation.
		 */
		kick_hrtimer();
	}
}

extern int task_isolation_syscall(int nr);

/* Report on exceptions that don't cause a signal for the user process. */
extern void _task_isolation_quiet_exception(const char *fmt, ...);
#define task_isolation_quiet_exception(fmt, ...)			\
	do {								\
		if (current_thread_info()->flags & _TIF_TASK_ISOLATION) \
			_task_isolation_quiet_exception(fmt, ## __VA_ARGS__); \
	} while (0)

extern void _task_isolation_debug(int cpu, const char *type);
#define task_isolation_debug(cpu, type)					\
	do {								\
		if (task_isolation_possible(cpu))			\
			_task_isolation_debug(cpu, type);		\
	} while (0)

extern void task_isolation_debug_cpumask(const struct cpumask *,
					 const char *type);
extern void task_isolation_debug_task(int cpu, struct task_struct *p,
				      const char *type);
void task_isolation_cpumask(struct cpumask *mask);

static inline bool is_isolation_cpu(int cpu)
{
	return task_isolation_map != NULL &&
		cpumask_test_cpu(cpu, task_isolation_map);
}

int task_isolation_on_cpu(int cpu);

#else
static inline void task_isolation_init(void) { }
static inline bool task_isolation_possible(int cpu) { return false; }
static inline bool task_isolation_ready(void) { return true; }
static inline void task_isolation_enter(void) { }
extern inline void task_isolation_set_flags(struct task_struct *p,
					    unsigned int flags) { }
static inline int task_isolation_syscall(int nr) { return 0; }
static inline void task_isolation_quiet_exception(const char *fmt, ...) { }
static inline void task_isolation_debug(int cpu, const char *type) { }
static inline void task_isolation_cpumask(struct cpumask *mask) { }
static inline bool is_isolation_cpu(int cpu) { return 0; }
#define task_isolation_debug_cpumask(mask, type) do {} while (0)
static inline int task_isolation_on_cpu(int cpu) { return 0; }
#endif

#endif
