/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019, Oracle and/or its affiliates. All rights reserved. */

#ifndef _ASM_ARM64_DTRACE_UTIL_H
#define _ASM_ARM64_DTRACE_UTIL_H

#include <asm/dtrace_arch.h>

extern asm_instr_t dtrace_text_peek(asm_instr_t *addr);
extern void dtrace_text_poke(asm_instr_t *addr, asm_instr_t opcode);
extern void dtrace_kernel_brk_start(void *arg);
extern void dtrace_kernel_brk_stop(void *arg);

#endif /* _ASM_ARM64_DTRACE_UTIL_H */
