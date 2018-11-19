/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	DTrace - OS support functions
 *
 * Copyright (c) 2010, 2018, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/binfmts.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_sdt.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>
#include <linux/init_task.h>
#include <linux/sched/mm.h>
#include <linux/shmem_fs.h>
#include <linux/dtrace_task_impl.h>

/*
 * OS SPECIFIC DTRACE SETUP
 */

/*
 * DTrace pseudo module that represents vmlinux (the kernel itself).
 * Since we populate its sdt data members only once, it can be marked
 * as RO after init.
 */
struct module		*dtrace_kmod __ro_after_init = NULL;
EXPORT_SYMBOL(dtrace_kmod);

int			dtrace_ustackdepth_max = 2048;

struct kmem_cache	*dtrace_pdata_cachep = NULL;

void __init dtrace_os_init(void)
{
	/*
	 * Setup for module handling.
	 */
	dtrace_pdata_cachep = kmem_cache_create("dtrace_pdata_cache",
				sizeof(struct dtrace_module), 0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	if (dtrace_pdata_cachep == NULL)
		pr_debug("Can't allocate kmem cache for pdata\n");

	/*
	 * A little bit of magic...
	 * We create a dummy module to represent the core Linux kernel.  The
	 * only data we're interested in is the name, the SDT probe points data
	 * (to be filled in by dtrace_sdt_register()), and the probe data.
	 * DTrace uses an architecture-specific structure (hidden from us here)
	 * to hold some data.
	 */
	dtrace_kmod = kmalloc(sizeof(struct module), GFP_KERNEL | __GFP_ZERO);
	if (dtrace_kmod == NULL) {
		pr_warn("%s: cannot allocate kernel pseudo-module\n",
			__func__);
		return;
	}

	strlcpy(dtrace_kmod->name, "vmlinux", MODULE_NAME_LEN);

	/*
	 * Some sizing info is required for kernel module. We are going to use
	 * modules VA range for trampoline anyway so lets pretend a kernel has
	 * no init section and VA range (0, MODULES_VADDR) is occupied by
	 * kernel itself
	 */
#ifdef CONFIG_X86_64
	dtrace_kmod->core_layout.base = (void *)__START_KERNEL_map;
	dtrace_kmod->core_layout.size = KERNEL_IMAGE_SIZE;
#elif defined(CONFIG_SPARC64)
	/* Hardcoded see pgtable_64.h */
	dtrace_kmod->core_layout.base = (void *)0x4000000;
	dtrace_kmod->core_layout.size = 0x2000000;
#endif

	dtrace_kmod->state = MODULE_STATE_LIVE;
	atomic_inc(&dtrace_kmod->refcnt);

	dtrace_mod_pdata_alloc(dtrace_kmod);

	INIT_LIST_HEAD(&dtrace_kmod->source_list);
	INIT_LIST_HEAD(&dtrace_kmod->target_list);

	/*
	 * We need to set up a psinfo structure for PID 0 (swapper).
	 */
	dtrace_task_os_init();
	dtrace_psinfo_os_init();
	dtrace_task_init(&init_task);
	dtrace_psinfo_alloc(&init_task);

	dtrace_sdt_init();
	dtrace_sdt_register(dtrace_kmod);
}

#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))
#define TRAMP_RANGE	0x80000000

void *dtrace_alloc_text(struct module *mp, unsigned long size)
{
	unsigned long mp_start, mp_end;
	unsigned long va_start, va_end;
	void *trampoline;

	/* module range */
	mp_start = (unsigned long) mp->core_layout.base;
	mp_end = mp_start + mp->core_layout.size;

	if (mp->init_layout.size) {
		mp_start = MIN(mp_start, (unsigned long)mp->init_layout.base);
		mp_end = MAX(mp_end, (unsigned long)mp->init_layout.base +
			     mp->init_layout.size);
	}

	/* get trampoline range */
	va_end = MIN(mp_start + TRAMP_RANGE, MODULES_END);
	va_start = (mp_end < TRAMP_RANGE) ? 0 : mp_end - TRAMP_RANGE;
	va_start = MAX(va_start, MODULES_VADDR);

	trampoline =  __vmalloc_node_range(size, 1, va_start, va_end,
				    GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));

	return trampoline;
}
EXPORT_SYMBOL(dtrace_alloc_text);

void dtrace_free_text(void *ptr)
{
	return vfree(ptr);
}
EXPORT_SYMBOL(dtrace_free_text);

/*
 * MODULE SUPPORT FUNCTIONS
 */
extern struct list_head *dtrace_modules;

/*
 * Iterate over all loaded kernel modules.  This is required until the linux
 * kernel receives its own module iterator.
 */
void dtrace_for_each_module(for_each_module_fn func, void *arg)
{
	struct module *mp;

	if (func == NULL)
		return;

	/* The dtrace fake module is not in the list. */
	func(arg, dtrace_kmod);

	list_for_each_entry(mp, dtrace_modules, list) {

#ifdef MODULES_VADDR
		if ((uintptr_t)mp < MODULES_VADDR ||
		    (uintptr_t)mp >= MODULES_END)
			continue;
#else
		if ((uintptr_t)mp < VMALLOC_START ||
		    (uintptr_t)mp >= VMALLOC_END)
			continue;
#endif

		func(arg, mp);
	}
}
EXPORT_SYMBOL_GPL(dtrace_for_each_module);


void dtrace_mod_pdata_alloc(struct module *mp)
{
	struct dtrace_module *pdata;

	pdata = kmem_cache_alloc(dtrace_pdata_cachep, GFP_KERNEL | __GFP_ZERO);
	if (pdata == NULL) {
		mp->pdata = NULL;
		return;
	}

	dtrace_mod_pdata_init(pdata);
	mp->pdata = pdata;
}

void dtrace_mod_pdata_free(struct module *mp)
{
	struct dtrace_module *pdata = mp->pdata;

	if (mp->pdata == NULL)
		return;

	mp->pdata = NULL;
	dtrace_mod_pdata_cleanup(pdata);
	kmem_cache_free(dtrace_pdata_cachep, pdata);
}

/*
 * This function is called with module_mutex held.
 */
int dtrace_destroy_prov(struct module *mp)
{
	struct dtrace_module *pdata = mp->pdata;

	if (pdata != NULL && pdata->prov_exit != NULL)
		return pdata->prov_exit();

	return 1;
}

/*---------------------------------------------------------------------------*\
(* TIME SUPPORT FUNCTIONS                                                    *)
\*---------------------------------------------------------------------------*/
enum dtrace_vtime_state	dtrace_vtime_active = 0;

/*
 * Until Linux kernel gains lock-free realtime clock access we are maintaining
 * our own version for lock-free access from within a probe context.
 */
static struct dtrace_time_fast {
	seqcount_t	dtwf_seq;
	ktime_t		dtwf_offsreal[2];
} dtrace_time ____cacheline_aligned;

/*
 * Callback from timekeeper code that allows dtrace to update its own time data.
 */
void dtrace_update_time(struct timekeeper *tk)
{
	raw_write_seqcount_latch(&dtrace_time.dtwf_seq);
	dtrace_time.dtwf_offsreal[0] = tk->offs_real;
	raw_write_seqcount_latch(&dtrace_time.dtwf_seq);
	dtrace_time.dtwf_offsreal[1] = tk->offs_real;
}

/* Lock free walltime */
ktime_t dtrace_get_walltime(void)
{
	u64 nsec = ktime_get_mono_fast_ns();
	unsigned int seq;
	ktime_t offset;

	do {
		seq = raw_read_seqcount_latch(&dtrace_time.dtwf_seq);
		offset = dtrace_time.dtwf_offsreal[seq & 0x1];
	} while (read_seqcount_retry(&dtrace_time.dtwf_seq, seq));

	return ktime_add_ns(offset, nsec);
}
EXPORT_SYMBOL(dtrace_get_walltime);

ktime_t dtrace_gethrtime(void)
{
	return ns_to_ktime(ktime_get_raw_fast_ns());
}
EXPORT_SYMBOL(dtrace_gethrtime);

/* Needed for lockstat probes where we cannot include ktime.h */
u64 dtrace_gethrtime_ns(void)
{
	return ktime_get_raw_fast_ns();
}
EXPORT_SYMBOL(dtrace_gethrtime_ns);

void dtrace_vtime_enable(void)
{
	enum dtrace_vtime_state	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_ACTIVE) {
			pr_warn_once("DTrace virtual time already enabled");
			return;
		}

		new = DTRACE_VTIME_ACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_enable);

void dtrace_vtime_disable(void)
{
	int	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_INACTIVE) {
			pr_warn_once("DTrace virtual time already disabled");
			return;
		}

		new = DTRACE_VTIME_INACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_disable);

void dtrace_vtime_switch(struct task_struct *prev, struct task_struct *next)
{
	struct dtrace_task *dprev = prev->dt_task;
	struct dtrace_task *dnext = next->dt_task;
	ktime_t	now = dtrace_gethrtime();

	if (dprev != NULL && ktime_nz(dprev->dt_start)) {
		dprev->dt_vtime = ktime_add(dprev->dt_vtime,
					       ktime_sub(now,
							 dprev->dt_start));
		dprev->dt_start = ktime_set(0, 0);
	}

	if (dnext != NULL)
		dnext->dt_start = now;
}

void dtrace_stacktrace(struct stacktrace_state *st)
{
	int	i;

	if ((st->flags & STACKTRACE_TYPE) == STACKTRACE_USER) {
		dtrace_user_stacktrace(st);
		return;
	}

	if (st->pcs == NULL) {
		st->depth = 0;
		return;
	}

	st->depth = stack_trace_save((long unsigned int *) st->pcs,
				     st->limit ? st->limit : 512, st->depth);

	/*
	 * For entirely unknown reasons, the save_stack_trace() implementation
	 * on x86_64 adds a ULONG_MAX entry after the last stack trace entry.
	 * This might be a sentinel value, but given that struct stack_trace
	 * already contains a nr_entries counter, this seems rather pointless.
	 * Alas, we need to add a special case for that...  And to make matters
	 * worse, it actually does this only when there is room for it (i.e.
	 * when nr_entries < max_entries).
	 * Since ULONG_MAX is never a valid PC, we can just check for that.
	 */
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
	if (st->depth && st->pcs[st->depth - 1] == ULONG_MAX)
		st->depth--;
#endif

	if (st->fps != NULL) {
		for (i = 0; i < st->limit; i++)
			st->fps[i] = 0;
	}
}
EXPORT_SYMBOL(dtrace_stacktrace);

/*
 * INVALID OPCODE AND PAGE FAULT HANDLING
 */
static struct notifier_block	dtrace_die = {
	.notifier_call = dtrace_die_notifier,
	.priority = 0x7fffffff
};

static int	dtrace_enabled;

/*
 * DTrace enable/disable must be called with dtrace_lock being held. It is not
 * possible to check for safety here with an ASSERT as the lock itself is in the
 * DTrace Framework kernel module.
 */
int dtrace_enable(void)
{
	if (dtrace_enabled)
		return 0;

	if (register_die_notifier(&dtrace_die) != 0)
		return 1;

	dtrace_enabled = 1;
	return 0;
}
EXPORT_SYMBOL(dtrace_enable);

void dtrace_disable(void)
{
	if (!dtrace_enabled)
		return;

	unregister_die_notifier(&dtrace_die);
	dtrace_enabled = 0;
}
EXPORT_SYMBOL(dtrace_disable);
