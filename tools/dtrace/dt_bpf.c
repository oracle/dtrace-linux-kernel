// SPDX-License-Identifier: GPL-2.0
/*
 * This file provides the interface for handling BPF.  It uses the bpf library
 * to interact with BPF ELF object files.
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#include "dtrace_impl.h"

/*
 * Validate the output buffer map that is specified in the BPF ELF object.  It
 * must match the following definition to be valid:
 *
 * struct bpf_map_def SEC("maps") buffers = {
 *	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
 *	.key_size = sizeof(u32),
 *	.value_size = sizeof(u32),
 *	.max_entries = num,
 * };
 * where num is greater than dt_maxcpuid.
 */
static int is_valid_buffers(const struct bpf_map_def *mdef)
{
	return mdef->type == BPF_MAP_TYPE_PERF_EVENT_ARRAY &&
	       mdef->key_size == sizeof(u32) &&
	       mdef->value_size == sizeof(u32) &&
	       mdef->max_entries > dt_maxcpuid;
}

/*
 * List the probes specified in the given BPF ELF object file.
 */
int dt_bpf_list_probes(const char *fn)
{
	struct bpf_object	*obj;
	struct bpf_program	*prog;
	int			rc, fd;

	libbpf_set_print(NULL);

	/*
	 * Listing probes is done before the DTrace command line utility loads
	 * the supplied programs.  We load them here without attaching them to
	 * probes so that we can retrieve the ELF section names for each BPF
	 * program.  The section name indicates the probe that the program is
	 * associated with.
	 */
	rc = bpf_prog_load(fn, BPF_PROG_TYPE_UNSPEC, &obj, &fd);
	if (rc)
		return rc;

	/*
	 * Loop through the programs in the BPF ELF object, and try to resolve
	 * the section names into probes.  Use the supplied callback function
	 * to emit the probe description.
	 */
	for (prog = bpf_program__next(NULL, obj); prog != NULL;
	     prog = bpf_program__next(prog, obj)) {
		struct dt_probe	*probe;

		probe = dt_probe_resolve_event(bpf_program__title(prog, false));

		printf("%5d %10s %17s %33s %s\n", probe->id,
		       probe->prv_name ? probe->prv_name : "",
		       probe->mod_name ? probe->mod_name : "",
		       probe->fun_name ? probe->fun_name : "",
		       probe->prb_name ? probe->prb_name : "");
	}


	/* Done with the BPF ELF object.  */
	bpf_object__close(obj);

	return 0;
}

/*
 * Load the given BPF ELF object file.
 */
int dt_bpf_load_file(const char *fn)
{
	struct bpf_object	*obj;
	struct bpf_map		*map;
	struct bpf_program	*prog;
	int			rc, fd;

	libbpf_set_print(NULL);

	/* Load the BPF ELF object file. */
	rc = bpf_prog_load(fn, BPF_PROG_TYPE_UNSPEC, &obj, &fd);
	if (rc)
		return rc;

	/* Validate buffers map. */
	map = bpf_object__find_map_by_name(obj, "buffers");
	if (map && is_valid_buffers(bpf_map__def(map)))
		dt_bufmap_fd = bpf_map__fd(map);
	else
		goto fail;

	/*
	 * Loop through the programs and resolve each into the matching probe.
	 * Attach the program to the probe.
	 */
	for (prog = bpf_program__next(NULL, obj); prog != NULL;
	     prog = bpf_program__next(prog, obj)) {
		struct dt_probe	*probe;

		probe = dt_probe_resolve_event(bpf_program__title(prog, false));
		if (!probe)
			return -ENOENT;
		if (probe->prov && probe->prov->attach)
			probe->prov->attach(bpf_program__title(prog, false),
					    bpf_program__fd(prog));
	}

	return 0;

fail:
	bpf_object__close(obj);
	return -EINVAL;
}

/*
 * Store the (key, value) pair in the map referenced by the given fd.
 */
int dt_bpf_map_update(int fd, const void *key, const void *val)
{
	union bpf_attr	attr;

	memset(&attr, 0, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (u64)(unsigned long)key;
	attr.value = (u64)(unsigned long)val;
	attr.flags = 0;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

/*
 * Attach a trace event and associate a BPF program with it.
 */
int dt_bpf_attach(int event_id, int bpf_fd)
{
	int			event_fd;
	int			rc;
	struct perf_event_attr	attr = {};

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = event_id;

	/*
	 * Register the event (based on its id), and obtain a fd.  It gets
	 * created as an enabled probe, so we don't have to explicitly enable
	 * it.
	 */
	event_fd = perf_event_open(&attr, -1, 0, -1, 0);
	if (event_fd < 0) {
		perror("sys_perf_event_open");
		return -1;
	}

	/* Associate the BPF program with the event. */
	rc = ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, bpf_fd);
	if (rc < 0) {
		perror("PERF_EVENT_IOC_SET_BPF");
		return -1;
	}

	return 0;
}
