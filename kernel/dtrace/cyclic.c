/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	cyclic.c
 * DESCRIPTION:	Minimal cyclic implementation
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

#include <linux/cpu.h>
#include <linux/cyclic.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

static int		omni_enabled;

#define _CYCLIC_CPU_UNDEF		(-1)
#define _CYCLIC_CPU_OMNI		(-2)
#define CYCLIC_IS_OMNI(cyc)		((cyc)->cpu == _CYCLIC_CPU_OMNI)

struct cyclic_work {
	struct work_struct	work;
	struct cyclic		*cyc;
};

struct cyclic {
	struct list_head		list;
	int				cpu;
	union {
		struct {
			struct cyc_time		when;
			struct cyc_handler	hdlr;
			uint32_t		pend;
			struct hrtimer		timr;
			struct cyclic_work	work;
		} cyc;
		struct {
			struct cyc_omni_handler	hdlr;
			struct list_head	cycl;
		} omni;
	};
};

static LIST_HEAD(cyclics);

static void cyclic_fire(struct work_struct *work)
{
	struct cyclic_work *cwork = (struct cyclic_work *)work;
	struct cyclic	   *cyc = cwork->cyc;
	uint32_t	   cpnd, npnd;

	do {
		/*
		 * We know that the 'pend' counter for the cyclic is non-zero.
		 * So, we can start with calling the handler at least once.
		 */
		(*cyc->cyc.hdlr.cyh_func)(cyc->cyc.hdlr.cyh_arg);

again:
		/*
		 * The 'pend' counter may be modified by cyclic_expire() while
		 * we go through this loop.  We use an atomic compare-and-set
		 * instruction to determine whether it got changed.  If so, we
		 * retrieve the updated 'pend' value and try this again.
		 *
		 * Note that when the cyclic is being removed, the hrtimer will
		 * be cancelled first, which ensures that 'pend' will no longer
		 * be incremented.  When that happens, this loop will simply
		 * run through the remaining pending calls, and terminate.
		 */
		cpnd = cyc->cyc.pend;
		npnd = cpnd - 1;
		if (cmpxchg(&cyc->cyc.pend, cpnd, npnd) != cpnd)
			goto again;
	} while (npnd > 0);
}

/*
 * Timer expiration handler for cyclic hrtimers.  Cyclic worker functions must
 * be able to perform a variety of tasks (including calling functions that
 * could sleep), and therefore they cannot be called from interrupt context.
 *
 * We schedule a workqueue to do the actual work.
 *
 * But... under heavy load it is possible that the hrtimer will expire again
 * before the workqueue had a chance to run.  That would lead to missed events
 * which isn't quite acceptable.  Therefore, we use a counter to record how
 * many times the timer has expired vs how many times the handler has been
 * called.  The counter is incremented by this function upon hrtimer expiration
 * and decremented by the cyclic_fire.  Note that the workqueue is responsible
 * for calling the handler multiple times if the counter indicates that multiple
 * invocation are pending.
 *
 * This function is called as hrtimer handler, and therefore runs in interrupt
 * context, which by definition will ensure that manipulation of the 'pend'
 * counter in the cyclic can be done without locking, and changes will appear
 * atomic to the cyclic_fire().
 *
 * Moral of the story: the handler may not get called at the absolute times as
 * requested, but it will be called the correct number of times.
 */
static enum hrtimer_restart cyclic_expire(struct hrtimer *timr)
{
	struct cyclic *cyc = container_of(timr, struct cyclic, cyc.timr);

	/*
	 * High priority cyclics call directly into their handler.  This means
	 * that the handler must satisfy all requirements for executing code in
	 * interrupt context.
	 */
	if (cyc->cyc.hdlr.cyh_level == CY_HIGH_LEVEL) {
		(*cyc->cyc.hdlr.cyh_func)(cyc->cyc.hdlr.cyh_arg);
		goto done;
	}

	/*
	 * Increment the 'pend' counter, in case the work is already set to
	 * run.  If the counter was 0 upon entry, we need to schedule the
	 * work.  If the increment wraps the counter back to 0, we admit
	 * defeat, and reset it to its max value.
	 */
	if (cyc->cyc.pend++ == 0)
		schedule_work_on(cyc->cpu,
				 (struct work_struct *)&cyc->cyc.work);
	else if (cyc->cyc.pend == 0)
		cyc->cyc.pend = UINT_MAX;

done:
	/*
	 * Prepare the timer for the next expiration.
	 */
	if (cyc->cyc.when.cyt_interval == CY_INTERVAL_INF)
		return HRTIMER_NORESTART;

	hrtimer_forward_now(timr, cyc->cyc.when.cyt_interval);

	return HRTIMER_RESTART;
}

struct cyclic *cyclic_new(int omni)
{
	struct cyclic *cyc;

	cyc = kmalloc(sizeof(struct cyclic), GFP_KERNEL);
	if (cyc == NULL)
		return NULL;

	INIT_LIST_HEAD(&cyc->list);

	if (!omni) {
		cyc->cpu = _CYCLIC_CPU_UNDEF;
		cyc->cyc.pend = 0;
		hrtimer_init(&cyc->cyc.timr, CLOCK_MONOTONIC,
			     HRTIMER_MODE_REL_PINNED);
		cyc->cyc.timr.function = cyclic_expire;
		cyc->cyc.work.cyc = cyc;
		INIT_WORK((struct work_struct *)&cyc->cyc.work, cyclic_fire);
	} else {
		cyc->cpu = _CYCLIC_CPU_OMNI;
		INIT_LIST_HEAD(&cyc->omni.cycl);
	}

	return cyc;
}

static inline void cyclic_restart(struct cyclic *cyc)
{
	if (cyc->cyc.when.cyt_interval == CY_INTERVAL_INF)
		return;

	if (cyc->cyc.when.cyt_when == 0)
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
	else
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);
}

/*
 * Add a new cyclic to the system.
 */
cyclic_id_t cyclic_add(struct cyc_handler *hdlr, struct cyc_time *when)
{
	struct cyclic *cyc;

	if (hdlr == NULL || when == NULL)
		return CYCLIC_NONE;

	cyc = cyclic_new(0);
	if (cyc == NULL)
		return CYCLIC_NONE;

	list_add(&cyc->list, &cyclics);
	cyc->cpu = smp_processor_id();
	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	cyclic_restart(cyc);

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add);

static void cyclic_omni_xcall(struct cyclic *cyc)
{
	cyclic_restart(cyc);
}

/*
 * Add a new cyclic to the system.
 */
static void cyclic_add_pinned(int cpu, struct cyclic *omni,
			      struct cyc_handler *hdlr, struct cyc_time *when)
{
	struct cyclic *cyc;

	cyc = cyclic_new(0);
	if (cyc == NULL)
		return;

	list_add(&cyc->list, &omni->omni.cycl);
	cyc->cpu = cpu;
	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	smp_call_function_single(cpu, (smp_call_func_t)cyclic_omni_xcall,
				 cyc, 1);
}

/*
 * Start a cyclic on a specific CPU as sub-cyclic to an omni-present cyclic.
 */
static void cyclic_omni_start(struct cyclic *omni, int cpu)
{
	struct cyc_time		when;
	struct cyc_handler	hdlr;

	omni->omni.hdlr.cyo_online(omni->omni.hdlr.cyo_arg, cpu, &hdlr, &when);
	cyclic_add_pinned(cpu, omni, &hdlr, &when);
}

#ifdef CONFIG_HOTPLUG_CPU
static int cyclic_cpu_offline(unsigned int cpu)
{
	struct cyclic *cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		struct cyclic *c, *n;

		if (!CYCLIC_IS_OMNI(cyc))
			continue;

		list_for_each_entry_safe(c, n, &cyc->omni.cycl, list) {
			if (c->cpu == cpu)
				cyclic_remove((cyclic_id_t)c);
		}
	}
	return 0;
}

static int cyclic_cpu_online(unsigned int cpu)
{
	struct cyclic *cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		struct cyclic *c, *n;

		if (!CYCLIC_IS_OMNI(cyc))
			continue;

		list_for_each_entry_safe(c, n, &cyc->omni.cycl, list) {
			if (c->cpu == cpu)
				break;
		}

		if (c->cpu == cpu)
			continue;

		cyclic_omni_start(cyc, cpu);
	}
	return 0;
}
#endif

/*
 * Add a new omnipresent cyclic to the system.
 */
cyclic_id_t cyclic_add_omni(struct cyc_omni_handler *omni)
{
	int		cpu;
	struct cyclic	*cyc;

	cyc = cyclic_new(1);
	if (cyc == NULL)
		return CYCLIC_NONE;

	list_add(&cyc->list, &cyclics);
	cyc->omni.hdlr = *omni;

	for_each_online_cpu(cpu)
		cyclic_omni_start(cyc, cpu);

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add_omni);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	struct cyclic	*cyc = (struct cyclic *)id;

	if (CYCLIC_IS_OMNI(cyc)) {
		struct cyclic *child, *n;

		/*
		 * If this is an omni-present cyclic, we first need to remove
		 * all the associated per-CPU cyclics.  Note that the recursive
		 * call into cyclic_remove() for a child cyclic will remove it
		 * from the list of per-CPU cyclics associated with the
		 * omni-present cyclic, so we do not need to handle that here.
		 */
		list_for_each_entry_safe(child, n, &cyc->omni.cycl, list)
			cyclic_remove((cyclic_id_t)child);
	} else {
		/*
		 * We know that hrtimer_cancel() will wait for the timer
		 * callback to finish if it is being executed at the time of
		 * making this call.  It is therefore guaranteed that 'pend'
		 * will no longer get incremented.
		 *
		 * The call to cancel_work_sync() will wait for the workqueue
		 * handler to finish also, and since the handler always brings
		 * 'pend' down to zero prior to returning, it is guaranteed that
		 * (1) all pending handler calls will be made before
		 *     cyclic_remove() returns
		 * (2) the amount of work to do before returning is finite.
		 */
		hrtimer_cancel(&cyc->cyc.timr);
		cancel_work_sync((struct work_struct *)&cyc->cyc.work);
	}

	list_del(&cyc->list);
	kfree(cyc);
}
EXPORT_SYMBOL(cyclic_remove);

struct cyclic_reprog {
	cyclic_id_t	cycid;
	ktime_t		delta;
};

static void cyclic_reprogram_xcall(struct cyclic_reprog *creprog)
{
	cyclic_reprogram(creprog->cycid, creprog->delta);
}

/*
 * Reprogram cyclic to fire with given delta from now.
 *
 * The underlying design makes it safe to call cyclic_reprogram from whithin a
 * cyclic handler without race with cyclic_remove. If called from outside of the
 * cyclic handler it is up to the owner to ensure to not call cyclic_reprogram
 * after call to cyclic_remove.
 *
 * This function cannot be called from interrupt/bottom half contexts.
 */
void cyclic_reprogram(cyclic_id_t id, ktime_t delta)
{
	struct cyclic *cyc = (struct cyclic *)id;

	/*
	 * For omni present cyclic we reprogram child for current CPU.
	 */
	if (CYCLIC_IS_OMNI(cyc)) {
		struct cyclic *c, *n;

		list_for_each_entry_safe(c, n, &cyc->omni.cycl, list) {
			if (c->cpu != smp_processor_id())
				continue;

			hrtimer_start(&c->cyc.timr, delta,
				      HRTIMER_MODE_ABS_PINNED);

			break;
		}

		return;
	}

	/*
	 * Regular cyclic reprogram must ensure that the timer remains bound
	 * to the CPU it was registered on. In case we are called from
	 * different CPU we use xcall to trigger reprogram from correct cpu.
	 */
	if (cyc->cpu != smp_processor_id()) {
		struct cyclic_reprog creprog = {
			.cycid = id,
			.delta = delta,
		};

		smp_call_function_single(cyc->cpu, (smp_call_func_t)
					 cyclic_reprogram_xcall, &creprog, 1);
	} else {
		hrtimer_start(&cyc->cyc.timr, delta, HRTIMER_MODE_REL_PINNED);
	}
}
EXPORT_SYMBOL(cyclic_reprogram);

static void *s_start(struct seq_file *seq, loff_t *pos)
{
	loff_t		n = *pos;
	struct cyclic	*cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		if (n == 0)
			return cyc;

		n--;
	}

	return NULL;
}

static void *s_next(struct seq_file *seq, void *p, loff_t *pos)
{
	struct cyclic	*cyc = p;

	++*pos;

	cyc = list_entry(cyc->list.next, struct cyclic, list);
	if (&cyc->list == &cyclics)
		return NULL;

	return cyc;
}

static void s_stop(struct seq_file *seq, void *p)
{
}

static int s_show(struct seq_file *seq, void *p)
{
	struct cyclic	*cyc = p;

	if (CYCLIC_IS_OMNI(cyc)) {
		struct cyclic	*c;

		seq_puts(seq, "Omni-present cyclic:\n");
		list_for_each_entry(c, &cyc->omni.cycl, list)
			seq_printf(seq,
				   "  CPU-%d: %c %lld ns hdlr %pB arg %llx\n",
				   c->cpu,
				   c->cyc.hdlr.cyh_level == CY_HIGH_LEVEL
					? 'H' : 'l',
				   c->cyc.when.cyt_interval,
				   c->cyc.hdlr.cyh_func,
				   (uint64_t)c->cyc.hdlr.cyh_arg);
	} else
		seq_printf(seq, "CPU-%d: %c %lld ns hdlr %pB arg %llx\n",
			   cyc->cpu,
			   cyc->cyc.hdlr.cyh_level == CY_HIGH_LEVEL
				? 'H' : 'l',
			   cyc->cyc.when.cyt_interval,
			   cyc->cyc.hdlr.cyh_func,
			   (uint64_t)cyc->cyc.hdlr.cyh_arg);

	return 0;
}

static const struct seq_operations	cyclicinfo_ops = {
	.start	= s_start,
	.next	= s_next,
	.stop	= s_stop,
	.show	= s_show,
};

static int cyclicinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cyclicinfo_ops);
}

static const struct proc_ops proc_cyclicinfo_ops = {
	.proc_open	= cyclicinfo_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

static int __init cyclic_init(void)
{
	int	ret;

	proc_create("cyclicinfo", 0400, NULL, &proc_cyclicinfo_ops);

#ifdef CONFIG_HOTPLUG_CPU
	if (!omni_enabled) {
		ret = cpuhp_setup_state_nocalls(CPUHP_AP_CYCLIC_STARTING,
						"Cyclic omni-timer starting",
						cyclic_cpu_online,
						cyclic_cpu_offline);
		if (ret)
			pr_warn_once("Cannot enable cyclic omni timer\n");
		else
			omni_enabled = 1;
	}
#endif

	return 0;
}
module_init(cyclic_init);
