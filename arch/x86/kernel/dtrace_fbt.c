/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:        dtrace_fbt.c
 * DESCRIPTION: Dynamic Tracing: FBT registration code (arch-specific)
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_fbt.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <asm/insn.h>
#include <asm/sections.h>

#define FBT_MOV_RSP_RBP_1	0x48
#define FBT_MOV_RSP_RBP_2	0x89
#define FBT_MOV_RSP_RBP_3	0xe5
#define FBT_PUSHL_EBP		0x55
#define FBT_NOP			0x90
#define FBT_RET_IMM16		0xc2
#define FBT_RET			0xc3
#define FBT_LEAVE		0xc9

#define BL_SENTRY(tp, nm)	extern tp nm;
#define BL_DENTRY(tp, nm)
#include "fbt_blacklist.h"
#undef BL_DENTRY
#undef BL_SENTRY

static void
dtrace_fbt_populate_bl(void)
{
#define	BL_SENTRY(tp, nm)	dtrace_fbt_bl_add((unsigned long)&nm, \
						  __stringify(nm));
#define BL_DENTRY(tp, nm)	dtrace_fbt_bl_add(0, __stringify(nm));
#include "fbt_blacklist.h"
#undef BL_SENTRY
#undef BL_DENTRY
}

void dtrace_fbt_init(fbt_add_probe_fn fbt_add_probe, struct module *mp,
		     void *arg)
{
	loff_t			pos;
	struct kallsym_iter	sym;
	asm_instr_t		*paddr = NULL;
	struct dt_fbt_bl_entry	*blent = NULL;

	/*
	 * Look up any unresolved symbols in the blacklist, and sort the list
	 * by ascending address.
	 */
	dtrace_fbt_populate_bl();
	blent = dtrace_fbt_bl_first();

	pos = 0;
	kallsyms_iter_reset(&sym, 0);
	while (kallsyms_iter_update(&sym, pos++, 0)) {
		asm_instr_t	*addr, *end;
		int		state = 0, insc = 0;
		void		*fbtp = NULL;

		/*
		 * There is no point considering non-function symbols for FBT,
		 * or symbols that have a zero size.  We could consider weak
		 * symbols but that gets quite complicated and there is no
		 * demands for that (so far).
		 */
		if (sym.type != 'T' && sym.type != 't')
			continue;
		if (!sym.size)
			continue;

		/*
		 * Handle only symbols that belong to the module we have been
		 * asked for.
		 */
		if (mp == dtrace_kmod && !core_kernel_text(sym.value))
			continue;

		/*
		 * Ensure we have not been given .init symbol from kallsyms
		 * interface. This could lead to memory corruption once DTrace
		 * tries to enable probe in already freed memory.
		 */
		if (mp != dtrace_kmod && !within_module_core(sym.value, mp))
			continue;

		/*
		 * See if the symbol is on the FBT's blacklist.  Since both
		 * iterators are workng in sort order by ascending address we
		 * can use concurrent traversal.
		 */
		while (blent != NULL &&
		       dtrace_fbt_bl_entry_addr(blent) < sym.value) {
			blent = dtrace_fbt_bl_next(blent);
		}
		if (dtrace_fbt_bl_entry_addr(blent) == sym.value)
			continue;

		/*
		 * No FBT tracing for DTrace functions, and functions that are
		 * crucial to probe processing.
		 * Also weed out symbols that are not relevant here.
		 */
		if (strncmp(sym.name, "dtrace_", 7) == 0)
			continue;
		if (strncmp(sym.name, "insn_", 5) == 0)
			continue;
		if (strncmp(sym.name, "inat_", 5) == 0)
			continue;
		if (strncmp(sym.name, "_GLOBAL_", 8) == 0)
			continue;
		if (strncmp(sym.name, "do_", 3) == 0)
			continue;
		if (strncmp(sym.name, "xen_", 4) == 0)
			continue;

		addr = (asm_instr_t *)sym.value;
		end = (asm_instr_t *)(sym.value + sym.size);

		/*
		 * FIXME:
		 * When there are multiple symbols for the same address, we
		 * should link them together as probes associated with the
		 * same function.  When a probe for that function is triggered
		 * all associated probes should fire.
		 *
		 * For now, we ignore duplicates.
		 */
		if (addr == paddr)
			continue;
		paddr = addr;

		while (addr < end) {
			struct insn	insn;
                        int		ret;

			insc++;

			switch (state) {
			case 0:	/* start of function */
				if (*addr == FBT_PUSHL_EBP) {
					fbt_add_probe(
						mp, sym.name,
						FBT_ENTRY, *addr, addr, 0,
						NULL, arg);
					state = 1;
				} else if (insc > 10)
					state = 2;
				break;
			case 1: /* look for ret */
				if (*addr == FBT_RET) {
					uintptr_t	off;

					off = addr - (asm_instr_t *)sym.value;
					fbtp = fbt_add_probe(
						mp, sym.name,
						FBT_RETURN, *addr, addr, off,
						fbtp, arg);
				}
				break;
			}

			if (state == 2)
				break;

                        ret = insn_decode_kernel(&insn, addr);
			if (ret < 0)
				continue;

			addr += insn.length;
		}
	}
}
EXPORT_SYMBOL(dtrace_fbt_init);
