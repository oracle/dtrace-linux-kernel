/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_syscall.c
 * DESCRIPTION:	Dynamic Tracing: system call tracing support (arch-specific)
 *
 * Copyright (C) 2010-2018 Oracle Corporation
 */

#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_syscall.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <asm/insn.h>
#include <asm/stacktrace.h>
#include <asm/syscalls.h>

/*
 * SYSTEM CALL TRACING SUPPORT
 */
void (*systrace_probe)(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
		       uintptr_t, uintptr_t, uintptr_t);

void systrace_stub(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
		   uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
		   uintptr_t arg5, uintptr_t arg6)
{
}

asmlinkage long systrace_syscall(const struct pt_regs *regs);

asmlinkage long dtrace_stub_ptregs(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
				   uintptr_t, uintptr_t, uintptr_t);

static struct systrace_info	systrace_info =
{
	&systrace_probe,
	systrace_stub,
	systrace_syscall,
	{},
	{
#define __SYSCALL_64(nr, sym, compat)		[nr] { __stringify(sym), },
#define __SYSCALL_COMMON(nr, sym, compat)	__SYSCALL_64(nr, sym, compat)
#define __SYSCALL_X32(nt, sym, compat)
#include <asm/syscalls_64.h>
	}
};

asmlinkage long systrace_syscall(const struct pt_regs *regs)
{
	long			rc = 0;
	unsigned long		sysnum;
	dtrace_id_t		id;
	struct dtrace_syscalls	*sc;

	sysnum = syscall_get_nr(current, (struct pt_regs *) regs);
	sc = &systrace_info.sysent[sysnum];

	/*
	 * Note: 64-bit syscall-specific.
	 */
	id = sc->stsy_entry;
	if (id != DTRACE_IDNONE)
		(*systrace_probe)(id, regs->di, regs->si, regs->dx,
				  regs->r10, regs->r8, regs->r9, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	if (sc->stsy_underlying != NULL)
		rc = (*sc->stsy_underlying)(regs);

	id = sc->stsy_return;
	if (id != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0, 0);

	return rc;
}

struct systrace_info *dtrace_syscalls_init(void)
{
	int			i;

	for (i = 0; i < NR_syscalls; i++) {
		systrace_info.sysent[i].stsy_tblent =
					(dt_sys_call_t *)&sys_call_table[i];
		systrace_info.sysent[i].stsy_underlying =
					(dt_sys_call_t)sys_call_table[i];
	}

	return &systrace_info;
}
EXPORT_SYMBOL(dtrace_syscalls_init);
