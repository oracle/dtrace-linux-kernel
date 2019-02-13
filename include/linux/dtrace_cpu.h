/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2004, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_CPU_H_
#define _LINUX_DTRACE_CPU_H_

#ifdef CONFIG_DTRACE

#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/rwlock.h>
#include <linux/dtrace_types.h>
#include <linux/dtrace_cpu_defines.h>
#include <asm/dtrace_cpuinfo.h>

struct cpu_core {
	uint16_t	cpuc_dtrace_flags;
	uint8_t		cpuc_dcpc_intr_state;
	uint8_t		cpuc_pad[CPUC_PADSIZE];
	uintptr_t	cpuc_dtrace_illval;
	struct mutex	cpuc_pid_lock;

	uintptr_t	cpu_dtrace_caller;
	struct pt_regs	*cpu_dtrace_regs;
	ktime_t		cpu_dtrace_chillmark;
	ktime_t		cpu_dtrace_chilled;
	rwlock_t	cpu_ft_lock;
	atomic64_t	cpuc_sync_requests;
	atomic64_t	cpuc_in_probe_ctx;
	dtrace_id_t	cpuc_current_probe;
};

DECLARE_PER_CPU_SHARED_ALIGNED(struct cpu_core, dtrace_cpu_core);

struct cpuinfo {
	processorid_t	cpu_id;
	psetid_t	cpu_pset;
	chipid_t	cpu_chip;
	lgrp_id_t	cpu_lgrp;
	cpuinfo_arch_t	*cpu_info;
};

DECLARE_PER_CPU_SHARED_ALIGNED(struct cpuinfo, dtrace_cpu_info);

/* ABI requirement: type names compiled into DTrace userspace.  */
typedef struct cpuinfo cpuinfo_t;

extern void dtrace_cpu_init(void);

#endif /* CONFIG_DTRACE */
#endif /* _LINUX_DTRACE_CPU_H_ */
