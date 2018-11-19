/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_SYSCALL_H_
#define _LINUX_DTRACE_SYSCALL_H_

#include <linux/types.h>
#include <linux/dtrace_os.h>
#include <asm/syscall.h>

#define DTRACE_SYSCALL_STUB(t, n)      SCE_##t,
enum dtrace_sce_id {
	SCE_NONE = 0,
#include <asm/dtrace_syscall.h>
	SCE_nr_stubs
};
#undef DTRACE_SYSCALL_STUB

#define DTRACE_SYSCALL_STUB(t, n) \
	asmlinkage long dtrace_stub_##n(uintptr_t, uintptr_t, uintptr_t, \
					uintptr_t, uintptr_t, uintptr_t, \
					uintptr_t);
#include <asm/dtrace_syscall.h>
#undef DTRACE_SYSCALL_STUB

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
typedef asmlinkage long (*dt_sys_call_t)(uintptr_t, uintptr_t, uintptr_t,
					 uintptr_t, uintptr_t, uintptr_t,
					 uintptr_t);

#define DTRACE_SYSCALL_WRAP_PREFIX ""
#else
#include <asm/dtrace_syscall_types.h>
#endif

struct dtrace_syscalls {
	const char	*name;
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	dt_sys_call_t	stsy_underlying;
	dt_sys_call_t	*stsy_tblent;
};

typedef void (*dtrace_systrace_probe_t)(dtrace_id_t, uintptr_t, uintptr_t,
					uintptr_t, uintptr_t, uintptr_t,
					uintptr_t, uintptr_t);

struct systrace_info {
	dtrace_systrace_probe_t	*probep;
	dtrace_systrace_probe_t	stub;
	dt_sys_call_t		syscall;
	dt_sys_call_t		stubs[SCE_nr_stubs];
	struct dtrace_syscalls	sysent[NR_syscalls];
};

extern struct systrace_info *dtrace_syscalls_init(void);

#endif /* _LINUX_DTRACE_SYSCALL_H_ */
