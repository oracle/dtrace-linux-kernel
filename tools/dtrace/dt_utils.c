// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtrace_impl.h"

#define BUF_SIZE	1024		/* max size for online cpu data */

int	dt_numcpus;			/* number of online CPUs */
int	dt_maxcpuid;			/* highest CPU id */
int	*dt_cpuids;			/* list of CPU ids */

/*
 * Populate the online CPU id information from sysfs data.  We only do this
 * once because we do not care about CPUs coming online after we started
 * tracing.  If a CPU goes offline during tracing, we do not care either
 * because that simply means that it won't be writing any new probe data into
 * its buffer.
 */
void cpu_list_populate(void)
{
	char buf[BUF_SIZE];
	int fd, cnt, start, end, i;
	int *cpu;
	char *p, *q;

	fd = open("/sys/devices/system/cpu/online", O_RDONLY);
	if (fd < 0)
		goto fail;
	cnt = read(fd, buf, sizeof(buf));
	close(fd);
	if (cnt <= 0)
		goto fail;

	/*
	 * The string should always end with a newline, but let's make sure.
	 */
	if (buf[cnt - 1] == '\n')
		buf[--cnt] = 0;

	/*
	 * Count how many CPUs we have.
	 */
	dt_numcpus = 0;
	p = buf;
	do {
		start = (int)strtol(p, &q, 10);
		switch (*q) {
		case '-':		/* range */
			p = q + 1;
			end = (int)strtol(p, &q, 10);
			dt_numcpus += end - start + 1;
			if (*q == 0) {	/* end of string */
				p = q;
				break;
			}
			if (*q != ',')
				goto fail;
			p = q + 1;
			break;
		case 0:			/* end of string */
			dt_numcpus++;
			p = q;
			break;
		case ',':	/* gap  */
			dt_numcpus++;
			p = q + 1;
			break;
		}
	} while (*p != 0);

	dt_cpuids = calloc(dt_numcpus,  sizeof(int));
	cpu = dt_cpuids;

	/*
	 * Fill in the CPU ids.
	 */
	p = buf;
	do {
		start = (int)strtol(p, &q, 10);
		switch (*q) {
		case '-':		/* range */
			p = q + 1;
			end = (int)strtol(p, &q, 10);
			for (i = start; i <= end; i++)
				*cpu++ = i;
			if (*q == 0) {	/* end of string */
				p = q;
				break;
			}
			if (*q != ',')
				goto fail;
			p = q + 1;
			break;
		case 0:			/* end of string */
			*cpu = start;
			p = q;
			break;
		case ',':	/* gap  */
			*cpu++ = start;
			p = q + 1;
			break;
		}
	} while (*p != 0);

	/* Record the highest CPU id of the set of online CPUs. */
	dt_maxcpuid = *(cpu - 1);

	return;
fail:
	if (dt_cpuids)
		free(dt_cpuids);

	dt_numcpus = 0;
	dt_maxcpuid = 0;
	dt_cpuids = NULL;
}

void cpu_list_free(void)
{
	free(dt_cpuids);
	dt_numcpus = 0;
	dt_maxcpuid = 0;
	dt_cpuids = NULL;
}
