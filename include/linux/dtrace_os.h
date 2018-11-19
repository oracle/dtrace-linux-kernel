/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_OS_H_
#define _LINUX_DTRACE_OS_H_

#ifndef HEADERS_CHECK

#ifdef CONFIG_DTRACE

#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/timekeeper_internal.h>
#include <asm/unistd.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_task.h>
#include <linux/dtrace_psinfo.h>

extern struct module	*dtrace_kmod;

extern void __init dtrace_os_init(void);
extern void __init dtrace_psinfo_os_init(void);
extern void __init dtrace_task_os_init(void);

extern void *dtrace_alloc_text(struct module *, unsigned long);
extern void dtrace_free_text(void *);

extern void dtrace_mod_pdata_alloc(struct module *);
extern void dtrace_mod_pdata_free(struct module *);
extern int dtrace_destroy_prov(struct module *);

extern int dtrace_enable(void);
extern void dtrace_disable(void);

extern ktime_t dtrace_gethrtime(void);
extern ktime_t dtrace_getwalltime(void);

enum dtrace_vtime_state {
	DTRACE_VTIME_INACTIVE = 0,
	DTRACE_VTIME_ACTIVE
};

extern enum dtrace_vtime_state dtrace_vtime_active;

typedef void for_each_module_fn(void *, struct module *);
extern void dtrace_for_each_module(for_each_module_fn *fn, void *arg);

extern void dtrace_update_time(struct timekeeper *);
extern ktime_t dtrace_get_walltime(void);

extern void dtrace_vtime_enable(void);
extern void dtrace_vtime_disable(void);
extern void dtrace_vtime_switch(struct task_struct *, struct task_struct *);

#include <asm/dtrace_util.h>

extern int dtrace_instr_size(const asm_instr_t *);

extern int dtrace_die_notifier(struct notifier_block *, unsigned long, void *);

#define STACKTRACE_KERNEL	0x01
#define STACKTRACE_USER		0x02
#define STACKTRACE_TYPE		0x0f

struct stacktrace_state {
	uint64_t	*pcs;
	uint64_t	*fps;
	int		limit;
	int		depth;
	int		flags;
};

extern void dtrace_stacktrace(struct stacktrace_state *);
extern void dtrace_user_stacktrace(struct stacktrace_state *);
extern void dtrace_handle_badaddr(struct pt_regs *);
extern void dtrace_mod_pdata_init(struct dtrace_module *pdata);
extern void dtrace_mod_pdata_cleanup(struct dtrace_module *pdata);

/*
 * This is only safe to call if we know this is a userspace fault
 * or that the call happens after early boot.
 */
static inline int dtrace_no_pf(struct pt_regs *regs)
{
	if (unlikely(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))) {
		dtrace_handle_badaddr(regs);
		return 1;
	}

	return 0;
}

extern void (*dtrace_helpers_cleanup)(struct task_struct *);
extern void (*dtrace_helpers_fork)(struct task_struct *, struct task_struct *);

#else

/*
 * See arch/x86/mm/fault.c.
 */

#define dtrace_no_pf(ignore) 0

/*
 * See kernel/timekeeper.c
 */
#define	dtrace_update_time(ignore)

/*
 * See kernel/dtrace/dtrace_os.c
 */
#define dtrace_mod_pdata_alloc(ignore)
#define dtrace_mod_pdata_free(ignore)
#define dtrace_destroy_prov(ignore) 1

#endif /* CONFIG_DTRACE */

#endif /* !HEADERS_CHECK */

#endif /* _LINUX_DTRACE_OS_H_ */
