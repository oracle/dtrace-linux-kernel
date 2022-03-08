/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dt_test_dev.c
 * DESCRIPTION:	DTrace - test provider device driver
 *
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
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
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <trace/syscall.h>
#include <asm/unistd.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "dt_test.h"

static dtrace_id_t	pid = DTRACE_IDNONE;
static int		enabled;

/*
 * Some arrays of structures of different sizes populated with
 * unchanging randomly-chosen numbers, for padding tests.
 */

static struct dt_test_int_char
{
	int foo;
	char bar;
} intish[2] __attribute__((used)) = { { 47204473, 48 },
				       { 18472, 62 } };

static struct dt_test_long_int
{
	long foo;
	int bar;
} longish[2] __attribute__((used)) = { { 43737975, 240724 },
					{ 24924709, 526 } };

static struct dt_test_longlong_long
{
	long long foo;
	long bar;
} longlongish[2] __attribute__((used)) = { { 4294479287, 4395957 },
					    { 5239637, 249750 } };

static struct dt_test_like_a_scatterlist
{
	unsigned long	a;
	unsigned int	b;
	unsigned int	c;
	u64	d;
	unsigned int	e;
} scatter_failure[2] __attribute__((used)) = { { .a = 1, .b = 2,
						 .c = 3, .d = 4, .e = 5 },
					       { .a = 6, .b = 7,
						 .c = 8, .d = 9, .e = 10 } };

void dt_test_provide(void *arg, const struct dtrace_probedesc *desc)
{
	dtrace_id_t probe;

	probe = dtrace_probe_lookup(dt_test_id, "dt_test", NULL, "test");
	if (probe != DTRACE_IDNONE)
		return;

	pid = dtrace_probe_create(dt_test_id, "dt_test", NULL, "test", 1, NULL);
}

int dt_test_enable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 1;

	return 0;
}

void dt_test_disable(void *arg, dtrace_id_t id, void *parg)
{
	enabled = 0;
}

void dt_test_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

void probe_p(dtrace_id_t pid, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
	      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
	      uintptr_t arg7, uintptr_t arg8, uintptr_t arg9)
{
}

/*
 * Direct calling into dtrace_probe() when passing more than 5 parameters to
 * the probe requires a stub function.  Otherwise we may not be able to get
 * to the value of all arguments correctly.
 */
void dt_test_probe(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
		   uintptr_t arg3, uintptr_t arg4, uintptr_t arg5,
		   uintptr_t arg6, uintptr_t arg7, uintptr_t arg8,
		   uintptr_t arg9)
{
	/*
	 * Yes, this is not nice.
	 * Not at all...
	 * But we're doing it anyway...
	 */
	typeof(probe_p) *probe_fn = (void *)&dtrace_probe;

	probe_fn(pid, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
		 arg9);
}

static long dt_test_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	if (enabled) {
		dt_test_probe(cmd, arg, 2ULL, 3ULL, 4ULL, 5ULL, 6ULL, 7ULL,
					8ULL, 9ULL);

		return 0;
	}

	if (DTRACE_PROBE_ENABLED(sdt__test))
		DTRACE_PROBE(sdt__test__is__enabled);

	DTRACE_PROBE(sdt__test);

	/*
	 * Test translation-to-nothing.
	 */
	DTRACE_PROBE(sdt__test__ioctl__file, int, cmd, int :, 666,
		     char * : (), 0, struct file *, file, int, arg);

	/*
	 * Probes with every valid count of args.
	 */
	DTRACE_PROBE(sdt__test__arg1, int, 1);
	DTRACE_PROBE(sdt__test__arg2, int, 1, int, 2);
	DTRACE_PROBE(sdt__test__arg3, int, 1, int, 2, int, 3);
	DTRACE_PROBE(sdt__test__arg4, int, 1, int, 2, int, 3, int, 4);
	DTRACE_PROBE(sdt__test__arg5, int, 1, int, 2, int, 3, int, 4, int, 5);
	DTRACE_PROBE(sdt__test__arg6, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6);
	DTRACE_PROBE(sdt__test__arg7, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7);
	DTRACE_PROBE(sdt__test__arg8, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8);
	DTRACE_PROBE(sdt__test__arg9, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9);
	DTRACE_PROBE(sdt__test__arga, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10);
	DTRACE_PROBE(sdt__test__argb, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11);
	DTRACE_PROBE(sdt__test__argc, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12);
	DTRACE_PROBE(sdt__test__argd, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13);
	DTRACE_PROBE(sdt__test__arge, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13, int, 14);
	DTRACE_PROBE(sdt__test__argf, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13, int, 14, int, 15);
	DTRACE_PROBE(sdt__test__argg, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13, int, 14, int, 15, int, 16);
	DTRACE_PROBE(sdt__test__argh, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13, int, 14, int, 15, int, 16, int, 17);
	DTRACE_PROBE(sdt__test__argi, int, 1, int, 2, int, 3, int, 4, int, 5, int, 6, int, 7, int, 8, int, 9, int, 10, int, 11, int, 12, int, 13, int, 14, int, 15, int, 16, int, 17, int, 18);

	return -EAGAIN;
}

static int dt_test_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dt_test_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dt_test_fops = {
	.owner  = THIS_MODULE,
	.unlocked_ioctl = dt_test_ioctl,
	.open   = dt_test_open,
	.release = dt_test_close,
};

static struct miscdevice dt_test_dev = {
	.minor = DT_DEV_DT_TEST_MINOR,
	.name = "dt_test",
	.nodename = "dtrace/provider/dt_test",
	.fops = &dt_test_fops,
};

int dt_test_dev_init(void)
{
	int	ret = 0;

	ret = misc_register(&dt_test_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       dt_test_dev.name, dt_test_dev.minor);

	return ret;
}

void dt_test_dev_exit(void)
{
	misc_deregister(&dt_test_dev);
}
