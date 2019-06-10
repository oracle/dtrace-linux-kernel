// SPDX-License-Identifier: GPL-2.0
/*
 * The Function Boundary Tracing (FBT) provider for DTrace.
 *
 * FBT probes are exposed by the kernel as kprobes.  They are listed in the
 * TRACEFS/available_filter_functions file.  Some kprobes are associated with
 * a specific kernel module, while most are in the core kernel.
 *
 * Mapping from event name to DTrace probe name:
 *
 *      <name>					fbt:vmlinux:<name>:entry
 *						fbt:vmlinux:<name>:return
 *   or
 *      <name> [<modname>]			fbt:<modname>:<name>:entry
 *						fbt:<modname>:<name>:return
 *
 * Mapping from BPF section name to DTrace probe name:
 *
 *      kprobe/<name>				fbt:vmlinux:<name>:entry
 *      kretprobe/<name>			fbt:vmlinux:<name>:return
 *
 * (Note that the BPF section does not carry information about the module that
 *  the function is found in.  This means that BPF section name cannot be used
 *  to distinguish between functions with the same name occurring in different
 *  modules.)
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dtrace_impl.h"

#define KPROBE_EVENTS	TRACEFS "kprobe_events"
#define PROBE_LIST	TRACEFS "available_filter_functions"

static const char	provname[] = "fbt";
static const char	modname[] = "vmlinux";

/*
 * Scan the PROBE_LIST file and add entry and return probes for every function
 * that is listed.
 */
static int fbt_populate(void)
{
	FILE			*f;
	char			buf[256];
	char			*p;

	f = fopen(PROBE_LIST, "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f)) {
		/*
		 * Here buf is either "funcname\n" or "funcname [modname]\n".
		 */
		p = strchr(buf, '\n');
		if (p) {
			*p = '\0';
			if (p > buf && *(--p) == ']')
				*p = '\0';
		} else {
			/* If we didn't see a newline, the line was too long.
			 * Report it, and continue until the end of the line.
			 */
			fprintf(stderr, "%s: Line too long: %s\n",
				PROBE_LIST, buf);
			do
				fgets(buf, sizeof(buf), f);
			while (strchr(buf, '\n') == NULL);
			continue;
		}

		/*
		 * Now buf is either "funcname" or "funcname [modname".  If
		 * there is no module name provided, we will use the default.
		 */
		p = strchr(buf, ' ');
		if (p) {
			*p++ = '\0';
			if (*p == '[')
				p++;
		}

		dt_probe_new(&dt_fbt, provname, p ? p : modname, buf, "entry");
		dt_probe_new(&dt_fbt, provname, p ? p : modname, buf, "return");
	}

	fclose(f);

	return 0;
}

#define ENTRY_PREFIX	"kprobe/"
#define EXIT_PREFIX	"kretprobe/"

/*
 * Perform a probe lookup based on an event name (BPF ELF section name).
 */
static struct dt_probe *fbt_resolve_event(const char *name)
{
	const char	*prbname;
	struct dt_probe	tmpl;
	struct dt_probe	*probe;

	if (!name)
		return NULL;

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

/*
 * Attach the given BPF program (identified by its file descriptor) to the
 * kprobe identified by the given section name.
 */
static int fbt_attach(const char *name, int bpf_fd)
{
	char    efn[256];
	char    buf[256];
	int	event_id, fd, rc;

	name += 7;				/* skip "kprobe/" */
	snprintf(buf, sizeof(buf), "p:%s %s\n", name, name);

	/*
	 * Register the kprobe with the tracing subsystem.  This will create
	 * a tracepoint event.
	 */
	fd = open(KPROBE_EVENTS, O_WRONLY | O_APPEND);
	if (fd < 0) {
		perror(KPROBE_EVENTS);
		return -1;
	}
	rc = write(fd, buf, strlen(buf));
	if (rc < 0) {
		perror(KPROBE_EVENTS);
		close(fd);
		return -1;
	}
	close(fd);

	/*
	 * Read the tracepoint event id for the kprobe we just registered.
	 */
	strcpy(efn, EVENTSFS);
	strcat(efn, "kprobes/");
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

	/*
	 * Attaching a BPF program (by file descriptor) to an event (by ID) is
	 * a generic operation provided by the BPF interface code.
	 */
	return dt_bpf_attach(event_id, bpf_fd);
}

struct dt_provider	dt_fbt = {
	.name		= "fbt",
	.populate	= &fbt_populate,
	.resolve_event	= &fbt_resolve_event,
	.attach		= &fbt_attach,
};
