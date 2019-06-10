// SPDX-License-Identifier: GPL-2.0
/*
 * The syscall provider for DTrace.
 *
 * System call probes are exposed by the kernel as tracepoint events in the
 * "syscalls" group.  Entry probe names start with "sys_enter_" and exit probes
 * start with "sys_exit_".
 *
 * Mapping from event name to DTrace probe name:
 *
 *	syscalls:sys_enter_<name>		syscall:vmlinux:<name>:entry
 *	syscalls:sys_exit_<name>		syscall:vmlinux:<name>:return
 *
 * Mapping from BPF section name to DTrace probe name:
 *
 *	tracepoint/syscalls/sys_enter_<name>	syscall:vmlinux:<name>:entry
 *	tracepoint/syscalls/sys_exit_<name>	syscall:vmlinux:<name>:return
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dtrace_impl.h"

static const char	provname[] = "syscall";
static const char	modname[] = "vmlinux";

#define PROBE_LIST	TRACEFS "available_events"

#define PROV_PREFIX	"syscalls:"
#define ENTRY_PREFIX	"sys_enter_"
#define EXIT_PREFIX	"sys_exit_"

/*
 * Scan the PROBE_LIST file and add probes for any syscalls events.
 */
static int syscall_populate(void)
{
	FILE			*f;
	char			buf[256];

	f = fopen(PROBE_LIST, "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f)) {
		char	*p;

		/* * Here buf is "group:event".  */
		p = strchr(buf, '\n');
		if (p)
			*p = '\0';
		else {
			/*
			 * If we didn't see a newline, the line was too long.
			 * Report it, and continue until the end of the line.
			 */
			fprintf(stderr, "%s: Line too long: %s\n",
				PROBE_LIST, buf);
			do
				fgets(buf, sizeof(buf), f);
			while (strchr(buf, '\n') == NULL);
			continue;
		}

		/* We need "group:" to match "syscalls:". */
		p = buf;
		if (memcmp(p, PROV_PREFIX, sizeof(PROV_PREFIX) - 1) != 0)
			continue;

		p += sizeof(PROV_PREFIX) - 1;
		/*
		 * Now p will be just "event", and we are only interested in
		 * events that match "sys_enter_*" or "sys_exit_*".
		 */
		if (!memcmp(p, ENTRY_PREFIX, sizeof(ENTRY_PREFIX) - 1)) {
			p += sizeof(ENTRY_PREFIX) - 1;
			dt_probe_new(&dt_syscall, provname, modname, p,
				     "entry");
		} else if (!memcmp(p, EXIT_PREFIX, sizeof(EXIT_PREFIX) - 1)) {
			p += sizeof(EXIT_PREFIX) - 1;
			dt_probe_new(&dt_syscall, provname, modname, p,
				     "return");
		}
	}

	fclose(f);

	return 0;
}

#define EVENT_PREFIX	"tracepoint/syscalls/"

/*
 * Perform a probe lookup based on an event name (BPF ELF section name).
 */
static struct dt_probe *systrace_resolve_event(const char *name)
{
	const char	*prbname;
	struct dt_probe	tmpl;
	struct dt_probe	*probe;

	if (!name)
		return NULL;

	/* Exclude anything that is not a syscalls tracepoint */
	if (strncmp(name, EVENT_PREFIX, sizeof(EVENT_PREFIX) - 1) != 0)
		return NULL;
	name += sizeof(EVENT_PREFIX) - 1;

	if (strncmp(name, ENTRY_PREFIX, sizeof(ENTRY_PREFIX) - 1) == 0) {
		name += sizeof(ENTRY_PREFIX) - 1;
		prbname = "entry";
	} else if (strncmp(name, EXIT_PREFIX, sizeof(EXIT_PREFIX) - 1) == 0) {
		name += sizeof(EXIT_PREFIX) - 1;
		prbname = "return";
	} else
		return NULL;

	memset(&tmpl, 0, sizeof(tmpl));
	tmpl.prv_name = provname;
	tmpl.mod_name = modname;
	tmpl.fun_name = name;
	tmpl.prb_name = prbname;

	probe = dt_probe_by_name(&tmpl);

	return probe;
}

#define SYSCALLSFS	EVENTSFS "syscalls/"

/*
 * Attach the given BPF program (identified by its file descriptor) to the
 * event identified by the given section name.
 */
static int syscall_attach(const char *name, int bpf_fd)
{
	char    efn[256];
	char    buf[256];
	int	event_id, fd, rc;

	name += sizeof(EVENT_PREFIX) - 1;
	strcpy(efn, SYSCALLSFS);
	strcat(efn, name);
	strcat(efn, "/id");

	fd = open(efn, O_RDONLY);
	if (fd < 0) {
		perror(efn);
		return -1;
	}
	rc = read(fd, buf, sizeof(buf));
	if (rc < 0 || rc >= sizeof(buf)) {
		perror(efn);
		close(fd);
		return -1;
	}
	close(fd);
	buf[rc] = '\0';
	event_id = atoi(buf);

	return dt_bpf_attach(event_id, bpf_fd);
}

struct dt_provider	dt_syscall = {
	.name		= "syscall",
	.populate	= &syscall_populate,
	.resolve_event	= &systrace_resolve_event,
	.attach		= &syscall_attach,
};
