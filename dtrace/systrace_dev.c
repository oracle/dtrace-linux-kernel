/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	systrace_dev.c
 * DESCRIPTION:	DTrace - systrace provider device driver
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

#include <linux/dtrace_syscall.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/unistd.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "systrace.h"

#define SYSTRACE_ARTIFICIAL_FRAMES	1

#define SYSTRACE_SHIFT			16
#define SYSTRACE_ENTRY(id)		((1 << SYSTRACE_SHIFT) | (id))
#define SYSTRACE_RETURN(id)		(id)
#define SYSTRACE_SYSNUM(x)		((int)(x) & ((1 << SYSTRACE_SHIFT) - 1))
#define SYSTRACE_ISENTRY(x)		((int)(x) >> SYSTRACE_SHIFT)

#if ((1 << SYSTRACE_SHIFT) <= NR_syscalls)
# error 1 << SYSTRACE_SHIFT must exceed number of system calls
#endif

static struct systrace_info	*systrace_info;

void systrace_provide(void *arg, const struct dtrace_probedesc *desc)
{
	int	failed_count = 0;
	int	i;

	ASSERT(systrace_info != NULL);

	if (desc != NULL)
		return;

	for (i = 0; i < NR_syscalls; i++) {
		const char		*nm = systrace_info->sysent[i].name;
		dtrace_id_t		id;
		int			sz;
		size_t			wrap_len;

		if (nm == NULL)
			continue;

		if (systrace_info->sysent[i].stsy_underlying == NULL)
			continue;

		wrap_len = strlen(DTRACE_SYSCALL_WRAP_PREFIX);
		sz = strlen(nm);
		if (sz > wrap_len &&
		    memcmp(nm, DTRACE_SYSCALL_WRAP_PREFIX, wrap_len) == 0) {
			nm += wrap_len;
			sz -= wrap_len;
		}
		if (sz > 4 && memcmp(nm, "sys_", 4) == 0)
			nm += 4;
		else if (sz > 5 && memcmp(nm, "stub_", 5) == 0)
			nm += 5;

		id = dtrace_probe_lookup(syscall_id, dtrace_kmod->name, nm,
					 "entry");
		if (id == DTRACE_IDNONE) {
			id = dtrace_probe_create(syscall_id, dtrace_kmod->name,
						 nm, "entry",
						 SYSTRACE_ARTIFICIAL_FRAMES,
						 (void *)((uintptr_t)SYSTRACE_ENTRY(i)));
			if (id == DTRACE_IDNONE)
				failed_count++;

			systrace_info->sysent[i].stsy_entry = DTRACE_IDNONE;
		}

		id = dtrace_probe_lookup(syscall_id, dtrace_kmod->name, nm,
					 "return");
		if (id == DTRACE_IDNONE) {
			id = dtrace_probe_create(syscall_id, dtrace_kmod->name,
						 nm, "return",
						 SYSTRACE_ARTIFICIAL_FRAMES,
						 (void *)((uintptr_t)SYSTRACE_RETURN(i)));
			if (id == DTRACE_IDNONE)
				failed_count++;

			systrace_info->sysent[i].stsy_return = DTRACE_IDNONE;
		}
	}

	if (failed_count > 0)
		pr_warn("systrace: Failed to provide %d probes (out of memory)\n", failed_count);
}

static dt_sys_call_t get_intercept(int sysnum)
{
	switch (sysnum) {
	default:
		return systrace_info->syscall;
#define DTRACE_SYSCALL_STUB(t, n) \
	case __NR_##n: \
		return systrace_info->stubs[SCE_##t];
#include <asm/dtrace_syscall.h>
#undef DTRACE_SYSCALL_STUB
	}
}

int systrace_enable(void *arg, dtrace_id_t id, void *parg)
{
	int			sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	struct dtrace_syscalls	*sc = &systrace_info->sysent[sysnum];
	int			enabled = sc->stsy_entry != DTRACE_IDNONE ||
					  sc->stsy_return != DTRACE_IDNONE;
	dt_sys_call_t		intercept = get_intercept(sysnum);

	if (!enabled) {
		if (cmpxchg(sc->stsy_tblent, sc->stsy_underlying,
			    intercept) != sc->stsy_underlying)
			return 1;
	} else
		ASSERT(*sc->stsy_tblent == intercept);

	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		sc->stsy_entry = id;
	else
		sc->stsy_return = id;

	return 0;
}

void systrace_disable(void *arg, dtrace_id_t id, void *parg)
{
	int			sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	struct dtrace_syscalls	*sc = &systrace_info->sysent[sysnum];
	int			enabled =
				(sc->stsy_entry != DTRACE_IDNONE ? 1 : 0) +
				(sc->stsy_return != DTRACE_IDNONE ? 1 : 0);
	dt_sys_call_t		intercept = get_intercept(sysnum);

	/*
	 * Every syscall can have 2 probes associated with it.  We need to keep
	 * the interceptor in place until the last probe is getting disabled.
	 */
	if (enabled == 1)
		(void)cmpxchg(sc->stsy_tblent, intercept, sc->stsy_underlying);

	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		sc->stsy_entry = DTRACE_IDNONE;
	else
		sc->stsy_return = DTRACE_IDNONE;
}

void systrace_destroy(void *arg, dtrace_id_t id, void *parg)
{
	int	sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);

	/*
	 * Nothing to be done here - just ensure our probe has been disabled.
	 */
	if (SYSTRACE_ISENTRY((uintptr_t)parg))
		ASSERT(systrace_info->sysent[sysnum].stsy_entry ==
		       DTRACE_IDNONE);
	else
		ASSERT(systrace_info->sysent[sysnum].stsy_return ==
		       DTRACE_IDNONE);
}

static int systrace_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int systrace_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations systrace_fops = {
	.owner  = THIS_MODULE,
	.open   = systrace_open,
	.release = systrace_close,
};

static struct miscdevice systrace_dev = {
	.minor = DT_DEV_SYSTRACE_MINOR,
	.name = "systrace",
	.nodename = "dtrace/provider/systrace",
	.fops = &systrace_fops,
};

int syscall_dev_init(void)
{
	int	ret = 0;

	systrace_info = dtrace_syscalls_init();

	ret = misc_register(&systrace_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       systrace_dev.name, systrace_dev.minor);

	*(systrace_info->probep) = (dtrace_systrace_probe_t)dtrace_probe;

	return ret;
}

void syscall_dev_exit(void)
{
	*(systrace_info->probep) = systrace_info->stub;

	misc_deregister(&systrace_dev);
}
