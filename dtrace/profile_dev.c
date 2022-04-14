/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	profile_dev.c
 * DESCRIPTION:	DTrace - profile provider device driver
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

#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <asm/irq_regs.h>
#include <asm/ptrace.h>

#include <linux/hardirq.h>
#include <linux/profile.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "profile.h"

#define PROF_NAMELEN		15
#define PROF_PROFILE		0
#define PROF_TICK		1
#define PROF_PREFIX_PROFILE	"profile-"
#define PROF_PREFIX_TICK	"tick-"

struct profile_probe {
	char		prof_name[PROF_NAMELEN];
	dtrace_id_t	prof_id;
	int		prof_kind;
	ktime_t		prof_interval;
	cyclic_id_t	prof_cyclic;
};

struct profile_probe_percpu {
	ktime_t		profc_expected;
	ktime_t		profc_interval;
	struct profile_probe	*profc_probe;
};

static ktime_t	profile_interval_min = KTIME_INIT(0, NANOSEC / 5000);
static int	profile_aframes;

static int	profile_rates[] = {
				    97, 199, 499, 997, 1999,
				    4001, 4999, 0, 0, 0,
				    0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0,
				  };
static int	profile_ticks[] = {
				    1, 10, 100, 500, 1000,
				    5000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0,
				  };

/*
 * profile_max defines the upper bound on the number of profile probes that
 * can exist (this is to prevent malicious or clumsy users from exhausing
 * system resources by creating a slew of profile probes). At mod load time,
 * this gets its value from PROFILE_MAX_DEFAULT or profile-max-probes if it's
 * present as module parameter.
 * FIXME: module parameter yet to be implemented.
 */
#define PROFILE_MAX_DEFAULT	1000	/* default max. number of probes */

static int	profile_max;		/* maximum number of profile probes */
static atomic_t	profile_total;		/* current number of profile probes */

static void profile_tick_fn(uintptr_t arg)
{
	struct profile_probe	*prof = (struct profile_probe *)arg;
	unsigned long	pc = 0, upc = 0;
	struct pt_regs	*regs = get_irq_regs();

	/*
	 * If regs == NULL, then we were called from from softirq context which
	 * also means that we didn't actually interrupt any processing (kernel
	 * or user space).
	 * If regs != NULL, then we did actually get called from hardirq
	 * because the timer interrupt did really interrupt something that was
	 * going on on the CPU (could be user mode or kernel mode).
	 */
	if (regs == NULL) {
		uint64_t	stack[8];

		dtrace_getpcstack(stack, 8, 0, NULL);
		pc = stack[7];
	} else if (user_mode(regs))
		upc = instruction_pointer(regs);
	else
		pc = instruction_pointer(regs);

	dtrace_probe(prof->prof_id, pc, upc, 0, 0, 0, 0, 0);
}

static void profile_prof_fn(uintptr_t arg)
{
	struct profile_probe_percpu *pcpu = (struct profile_probe_percpu *)arg;
	struct profile_probe	*prof = pcpu->profc_probe;
	ktime_t			late;
	struct pt_regs		*regs = get_irq_regs();
	unsigned long		pc = 0, upc = 0;

	late = ktime_sub(dtrace_gethrtime(), pcpu->profc_expected);
	pcpu->profc_expected = ktime_add(pcpu->profc_expected,
					 pcpu->profc_interval);

	/*
	 * If regs == NULL, then we were called from from softirq context which
	 * also means that we didn't actually interrupt any processing (kernel
	 * or user space).
	 * If regs != NULL, then we did actually get called from hardirq
	 * because the timer interrupt did really interrupt something that was
	 * going on on the CPU (could be user mode or kernel mode).
	 */
	if (regs == NULL) {
		uint64_t	stack[8];

		dtrace_getpcstack(stack, 8, 0, NULL);
		pc = stack[7];
	} else if (user_mode(regs))
		upc = instruction_pointer(regs);
	else
		pc = instruction_pointer(regs);

	dtrace_probe(prof->prof_id, pc, upc, ktime_to_ns(late), 0, 0, 0, 0);
}

static void profile_online(void *arg, processorid_t cpu,
			   struct cyc_handler *hdlr,
			   struct cyc_time *when)
{
	struct profile_probe		*prof = arg;
	struct profile_probe_percpu	*pcpu;

	pcpu = kzalloc(sizeof(struct profile_probe_percpu), GFP_KERNEL);
	pcpu->profc_probe = prof;

	hdlr->cyh_func = profile_prof_fn;
	hdlr->cyh_arg = (uintptr_t)pcpu;
	hdlr->cyh_level = CY_HIGH_LEVEL;

	when->cyt_interval = prof->prof_interval;
	when->cyt_when = ktime_add(dtrace_gethrtime(), when->cyt_interval);

	pcpu->profc_expected = when->cyt_when;
	pcpu->profc_interval = when->cyt_interval;
}

static void profile_offline(void *arg, processorid_t cpu, void *oarg)
{
	struct profile_probe_percpu	*pcpu = oarg;

	if (pcpu->profc_probe == arg) {
		kfree(pcpu);
		return;
	}

	WARN_ONCE(1, "%s: called with mismatched probe info (%p vs %p)"
		  " - leaking %lu bytes\n", __func__, pcpu->profc_probe, arg,
		  sizeof(struct profile_probe_percpu));

}

static void profile_create(ktime_t interval, const char *name, int kind)
{
	struct profile_probe	*prof;
	int			nr_frames = 0; /* FIXME */

	if (profile_aframes)
		nr_frames = profile_aframes;

	if (ktime_lt(interval, profile_interval_min))
		return;

	if (dtrace_probe_lookup(profile_id, NULL, NULL, name) != 0)
		return;

	prof = kzalloc(sizeof(struct profile_probe), GFP_KERNEL);
	if (prof == NULL) {
		pr_warn("Unable to create probe %s: out of memory\n", name);
		return;
	}

	atomic_inc(&profile_total);
	if (atomic_read(&profile_total) > profile_max)
		goto errout;

	strcpy(prof->prof_name, name);
	prof->prof_interval = interval;
	prof->prof_cyclic = CYCLIC_NONE;
	prof->prof_kind = kind;
	prof->prof_id = dtrace_probe_create(profile_id, NULL, NULL, name,
					    nr_frames, prof);

	if (prof->prof_id == DTRACE_IDNONE) {
		pr_warn("Unable to create probe %s: out of memory\n", name);
		goto errout;
	}

	return;

errout:
	kfree(prof);
	atomic_dec(&profile_total);
	return;
}

void profile_provide(void *arg, const struct dtrace_probedesc *desc)
{
	int		i, j, rate, kind;
	long		val = 0, mult = 1, mult_s = 0, mult_ns = 0, len;
	ktime_t		interval;
	const char	*name, *suffix = NULL;
	const struct {
			char	*prefix;
			int	kind;
	} types[] = {
			{ PROF_PREFIX_PROFILE, PROF_PROFILE },
			{ PROF_PREFIX_TICK, PROF_TICK },
			{ NULL, 0 },
		    };

	const struct {
			char	*name;
			long	mult_s;
			long	mult_ns;
	} suffixes[] = {
			{ "ns",		0, 1 },
			{ "nsec",	0, 1 },
			{ "us",		0, NANOSEC / MICROSEC },
			{ "usec",	0, NANOSEC / MICROSEC },
			{ "ms",		0, NANOSEC / MILLISEC },
			{ "msec",	0, NANOSEC / MILLISEC },
			{ "s",		1, 0 },
			{ "sec",	1, 0 },
			{ "m",		60, 0 },
			{ "min",	60, 0 },
			{ "h",		60 * 60, 0 },
			{ "hour",	60 * 60, 0 },
			{ "d",		24 * 60 * 60, 0 },
			{ "day",	24 * 60 * 60, 0 },
			{ "hz",		0, 0 },
			{ NULL, },
		       };

	if (desc == NULL) {
		char	n[PROF_NAMELEN];

		/*
		 * If no description was provided, provide all of our probes.
		 */
		for (i = 0; i < sizeof(profile_rates) / sizeof(int); i++) {
			rate = profile_rates[i];
			if (rate == 0)
				continue;

			snprintf(n, PROF_NAMELEN, "%s%d",
				 PROF_PREFIX_PROFILE, rate);
			profile_create(ktime_set(0, NANOSEC / rate),
				       n, PROF_PROFILE);
		}

		for (i = 0; i < sizeof(profile_ticks) / sizeof(int); i++) {
			rate = profile_ticks[i];
			if (rate == 0)
				continue;

			snprintf(n, PROF_NAMELEN, "%s%d",
				 PROF_PREFIX_TICK, rate);
			profile_create(ktime_set(0, NANOSEC / rate),
				       n, PROF_TICK);
		}

		return;
	}

	name = desc->dtpd_name;

	for (i = 0; types[i].prefix != NULL; i++) {
		len = strlen(types[i].prefix);

		if (strncmp(name, types[i].prefix, len) != 0)
			continue;

		break;
	}

	if (types[i].prefix == NULL)
		return;

	kind = types[i].kind;

	/*
	 * We need to start before any time suffix.
	 */
	for (j = strlen(name); j >= len; j--) {
		if (name[j] >= '0' && name[j] <= '9')
			break;

		suffix = &name[j];
	}

	if (suffix == NULL) {
		WARN_ONCE(1, "%s: missing time suffix in %s\n", __func__, name);
		return;
	}

	/*
	 * Now determine the numerical value present in the probe name.
	 */
	for (; j >= len; j--) {
		if (name[j] < '0' || name[j] > '9')
			return;

		val += (name[j] - '0') * mult;
		mult *= 10;
	}

	if (val == 0)
		return;

	/*
	 * Look up the suffix to determine the multiplier.
	 */
	for (i = 0; suffixes[i].name != NULL; i++) {
		if (strcasecmp(suffixes[i].name, suffix) == 0) {
			mult_s = suffixes[i].mult_s;
			mult_ns = suffixes[i].mult_ns;
			break;
		}
	}

	if (suffixes[i].name == NULL && *suffix != '\0')
		return;

	if (mult_s == 0 && mult_ns == 0) {
		/*
		 * The default is frequency (per-second).
		 */
		interval = ns_to_ktime((int64_t)NANOSEC / val);
	} else {
		long	sec;
		long	nsec = val * mult_ns;

		sec = nsec / NANOSEC;
		nsec %= NANOSEC;

		interval = ktime_set(val * mult_s + sec, nsec);
	}


	profile_create(interval, name, kind);
}

int profile_enable(void *arg, dtrace_id_t id, void *parg)
{
	struct profile_probe	*prof = parg;
	struct cyc_time		when;

	if (!ktime_nz(prof->prof_interval)) {
		WARN_ONCE(1, "%s: trying to enable 0-interval probe %s\n",
			  __func__, prof->prof_name);
		return 1;
	}
	if (!MUTEX_HELD(&cpu_lock)) {
		WARN_ONCE(1, "%s: not holding cpu_lock\n", __func__);
		return 1;
	}

	if (prof->prof_kind == PROF_TICK) {
		struct cyc_handler	hdlr;

		hdlr.cyh_func = profile_tick_fn;
		hdlr.cyh_arg = (uintptr_t)prof;
		hdlr.cyh_level = CY_HIGH_LEVEL;

		when.cyt_interval = prof->prof_interval;
		when.cyt_when = ktime_set(0, 0);

		prof->prof_cyclic = cyclic_add(&hdlr, &when);
	} else if (prof->prof_kind == PROF_PROFILE) {
		struct cyc_omni_handler	omni;

		omni.cyo_online = profile_online;
		omni.cyo_offline = profile_offline;
		omni.cyo_arg = prof;

		prof->prof_cyclic = cyclic_add_omni(&omni);
	} else
		pr_warn_once("%s: Invalid profile type %d\n",
			      __func__, prof->prof_kind);

	return 0;
}

void profile_disable(void *arg, dtrace_id_t id, void *parg)
{
	struct profile_probe	*prof = parg;

	if (prof->prof_cyclic == CYCLIC_NONE) {
		WARN_ONCE(1, "%s: trying to disable probe %s without cyclic\n",
			  __func__, prof->prof_name);
		return;
	}
	if (!MUTEX_HELD(&cpu_lock)) {
		WARN_ONCE(1, "%s: not holding cpu_lock\n", __func__);
		return;
	}

	cyclic_remove(prof->prof_cyclic);
	prof->prof_cyclic = CYCLIC_NONE;
}

int profile_usermode(void *arg, dtrace_id_t id, void *parg)
{
	return 1; /* FIXME: awaiting unprivileged tracing */
}

void profile_destroy(void *arg, dtrace_id_t id, void *parg)
{
	struct profile_probe	*prof = parg;

	if (prof->prof_cyclic == CYCLIC_NONE) {
		kfree(prof);

		if (atomic_read(&profile_total) >= 1) {
			atomic_dec(&profile_total);
			return;
		}

		WARN_ONCE(1, "%s: profile_total refcount is 0!\n", __func__);
	}

	WARN_ONCE(1, "%s: %s still assigned to cyclic\n",
		  __func__, prof->prof_name);
}

static int profile_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int profile_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations profile_fops = {
	.owner  = THIS_MODULE,
	.open   = profile_open,
	.release = profile_close,
};

static struct miscdevice profile_dev = {
	.minor = DT_DEV_PROFILE_MINOR,
	.name = "profile",
	.nodename = "dtrace/provider/profile",
	.fops = &profile_fops,
};

int profile_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&profile_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       profile_dev.name, profile_dev.minor);

	profile_max = PROFILE_MAX_DEFAULT;

	return ret;
}

void profile_dev_exit(void)
{
	misc_deregister(&profile_dev);
}
