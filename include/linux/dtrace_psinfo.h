/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_PSINFO_H_
#define _LINUX_DTRACE_PSINFO_H_

#ifdef CONFIG_DTRACE

#define PR_PSARGS_SZ		80
#define PR_ARGV_SZ		512
#define PR_ENVP_SZ		512

/*
 * DTrace's per-process info (per-tgid).
 *
 * All threads in a process share the same structure instance.
 */
struct dtrace_psinfo {
	atomic_t	dtps_usage;
	unsigned long	dtps_argc;
	char		**dtps_argv;
	unsigned long	dtps_envc;
	char		**dtps_envp;
	char		dtps_psargs[PR_PSARGS_SZ];
};

/*
 * DTrace psinfo API. Requires struct dtrace_task as its argument.
 */

extern void dtrace_psinfo_alloc(struct task_struct *);
extern void dtrace_psinfo_free(struct dtrace_psinfo *);

static inline void dtrace_psinfo_get(struct dtrace_psinfo *psinfo)
{
	if (likely(psinfo))
		atomic_inc(&(psinfo)->dtps_usage);
}

static inline void dtrace_psinfo_put(struct dtrace_psinfo *psinfo)
{
	if (likely((psinfo))) {
		if (atomic_dec_and_test(&(psinfo)->dtps_usage))
			dtrace_psinfo_free(psinfo);
	}
}

#else /* CONFIG_DTRACE */

#define dtrace_psinfo_alloc(ignore)
#define dtrace_psinfo_free(ignore)
#define dtrace_psinfo_get(ignore)
#define dtrace_psinfo_put(ignore)

#endif /* CONFIG_DTRACE */

#endif /* _LINUX_DTRACE_PSINFO_H_ */
