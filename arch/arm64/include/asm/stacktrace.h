/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_STACKTRACE_H
#define __ASM_STACKTRACE_H

struct task_struct;

struct stackframe {
	unsigned long fp;
	unsigned long sp;
	unsigned long pc;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	unsigned int graph;
#endif
};

extern int unwind_frame(struct task_struct *tsk, struct stackframe *frame);
extern void walk_stackframe(struct task_struct *tsk, struct stackframe *frame,
			    int (*fn)(struct stackframe *, void *), void *data);

static __always_inline void prepare_frametrace(struct pt_regs *regs)
{
	__asm__ __volatile__(
			"1: adr x0, 1b\n\t"
			"str x0, %0\n\t"
			"str x30, %1\n\t"
			"str x29, %2\n\t"
			: "=m" ((regs)->pc),
			"=m" ((regs)->regs[30]), "=m" ((regs)->regs[29])
			: : "memory", "x0");
}
#endif	/* __ASM_STACKTRACE_H */
