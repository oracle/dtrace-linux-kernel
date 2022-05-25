/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2013, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _X86_DTRACE_UTIL_H
#define _X86_DTRACE_UTIL_H

#define DTRACE_INVOP_NOPS		0x0f	/* 5-byte NOP sequence */
#define DTRACE_INVOP_MOV_RSP_RBP	0x48	/* mov %rsp, %rbp = 48 89 e5 */
#define DTRACE_INVOP_PUSH_BP		0x55	/* push %rbp = 55 */
#define DTRACE_INVOP_NOP		0x90	/* nop = 90 */
#define DTRACE_INVOP_LEAVE		0xc9	/* leave = c9 */
#define DTRACE_INVOP_RET		0xc3	/* ret = c3 */

#ifndef __ASSEMBLY__

#include <asm/dtrace_arch.h>
#include <asm/ptrace.h>

extern int dtrace_invop_add(uint8_t (*func)(struct pt_regs *));
extern void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *));

extern void dtrace_invop_enable(asm_instr_t *, asm_instr_t);
extern void dtrace_invop_disable(asm_instr_t *, asm_instr_t);

#endif

#endif /* _X86_DTRACE_UTIL_H */
