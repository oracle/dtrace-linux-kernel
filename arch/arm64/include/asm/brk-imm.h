/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ASM_BRK_IMM_H
#define __ASM_BRK_IMM_H

/*
 * #imm16 values used for BRK instruction generation
 * 0x004: for installing kprobes
 * 0x005: for installing uprobes
 * 0x006: for installing DTrace SDT probes
 * 0x007: for installing DTrace function-boundary tracing entry probes
 * 0x008: for installing DTrace function-boundary tracing return probes
 * Allowed values for kgdb are 0x400 - 0x7ff
 * 0x100: for triggering a fault on purpose (reserved)
 * 0x400: for dynamic BRK instruction
 * 0x401: for compile time BRK instruction
 * 0x800: kernel-mode BUG() and WARN() traps
 * 0x9xx: tag-based KASAN trap (allowed values 0x900 - 0x9ff)
 */
#define KPROBES_BRK_IMM			0x004
#define UPROBES_BRK_IMM			0x005
#define DPROBES_SDT_BRK_IMM		0x006
#define DPROBES_FBE_BRK_IMM		0x007
#define DPROBES_FBR_BRK_IMM		0x008
#define FAULT_BRK_IMM			0x100
#define KGDB_DYN_DBG_BRK_IMM		0x400
#define KGDB_COMPILED_DBG_BRK_IMM	0x401
#define BUG_BRK_IMM			0x800
#define KASAN_BRK_IMM			0x900
#define KASAN_BRK_MASK			0x0ff

#endif
