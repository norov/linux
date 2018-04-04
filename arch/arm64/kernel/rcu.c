/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/barrier.h>

void rcu_dynticks_eqs_exit_sync(void)
{
	isb();
};
