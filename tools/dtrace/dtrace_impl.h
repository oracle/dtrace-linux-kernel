/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _DTRACE_H
#define _DTRACE_H

#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#include "dtrace.h"

#define DT_DEBUG

#define DT_VERS_STRING	"Oracle D 2.0.0"

#define TRACEFS		"/sys/kernel/debug/tracing/"
#define EVENTSFS	TRACEFS "events/"

extern int	dt_numcpus;
extern int	dt_maxcpuid;
extern int	*dt_cpuids;

extern void cpu_list_populate(void);
extern void cpu_list_free(void);

struct dt_provider {
	char		*name;
	int		(*populate)(void);
	struct dt_probe *(*resolve_event)(const char *name);
	int		(*attach)(const char *name, int bpf_fd);
};

extern struct dt_provider	dt_fbt;
extern struct dt_provider	dt_syscall;

struct dt_hentry {
	struct dt_probe		*next;
	struct dt_probe		*prev;
};

struct dt_htab;

typedef u32 (*dt_hval_fn)(const struct dt_probe *);
typedef int (*dt_cmp_fn)(const struct dt_probe *, const struct dt_probe *);
typedef struct dt_probe *(*dt_add_fn)(struct dt_probe *, struct dt_probe *);
typedef struct dt_probe *(*dt_del_fn)(struct dt_probe *, struct dt_probe *);

extern struct dt_htab *dt_htab_new(dt_hval_fn hval, dt_cmp_fn cmp,
				   dt_add_fn add, dt_del_fn del);
extern int dt_htab_add(struct dt_htab *htab, struct dt_probe *probe);
extern struct dt_probe *dt_htab_lookup(const struct dt_htab *htab,
				       const struct dt_probe *probe);
extern int dt_htab_del(struct dt_htab *htab, struct dt_probe *probe);

struct dt_probe {
	u32				id;
	int				event_fd;
	const struct dt_provider	*prov;
	const char			*prv_name;	/* provider name */
	const char			*mod_name;	/* module name */
	const char			*fun_name;	/* function name */
	const char			*prb_name;	/* probe name */
	struct dt_hentry		he_fqn;
};

typedef void (*dt_probe_fn)(const struct dt_probe *probe);

extern int dt_probe_init(void);
extern int dt_probe_new(const struct dt_provider *prov, const char *pname,
			const char *mname, const char *fname, const char *name);
extern struct dt_probe *dt_probe_by_name(const struct dt_probe *tmpl);
extern struct dt_probe *dt_probe_resolve_event(const char *name);

extern int dt_bpf_list_probes(const char *fn);
extern int dt_bpf_load_file(const char *fn);
extern int dt_bpf_map_update(int fd, const void *key, const void *val);
extern int dt_bpf_attach(int event_id, int bpf_fd);

extern int dt_bufmap_fd;

extern int dt_buffer_init(int num_pages);
extern int dt_buffer_poll(int epoll_fd, int timeout);
extern void dt_buffer_exit(int epoll_fd);

static inline int perf_event_open(struct perf_event_attr *attr, pid_t pid,
				  int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

extern inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(union bpf_attr));
}

#endif /* _DTRACE_H */
