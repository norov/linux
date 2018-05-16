/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_SIGNAL32_H
#define __ASM_SIGNAL32_H

#ifdef __KERNEL__

#ifdef CONFIG_AARCH32_EL0

#include <linux/compat.h>

int a32_setup_frame(int usig, struct ksignal *ksig, sigset_t *set,
		       struct pt_regs *regs);

int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);

void a32_setup_restart_syscall(struct pt_regs *regs);
#else

static inline int a32_setup_frame(int usid, struct ksignal *ksig,
				     sigset_t *set, struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
					struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline void a32_setup_restart_syscall(struct pt_regs *regs)
{
}
#endif /* CONFIG_AARCH32_EL0 */
#endif /* __KERNEL__ */
#endif /* __ASM_SIGNAL32_H */
