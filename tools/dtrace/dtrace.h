/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _UAPI_LINUX_DTRACE_H
#define _UAPI_LINUX_DTRACE_H

struct dt_bpf_context {
	u32		probe_id;
	u64		argv[10];
};

#endif /* _UAPI_LINUX_DTRACE_H */
