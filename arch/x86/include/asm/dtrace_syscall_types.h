/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/types.h>
#include <linux/dtrace_types.h>

typedef asmlinkage long (*dt_sys_call_t)(const struct pt_regs *regs);

#define DTRACE_SYSCALL_WRAP_PREFIX "__x64_"
