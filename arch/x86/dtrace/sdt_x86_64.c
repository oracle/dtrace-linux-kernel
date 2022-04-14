/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	sdt_dev.c
 * DESCRIPTION:	DTrace - SDT provider implementation for x86
 *
 * Copyright (c) 2010, 2018, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/dtrace_util.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

#define SDT_PATCHVAL		0xf0

static uint8_t sdt_invop(struct pt_regs *regs)
{
	struct sdt_probe	*sdt = sdt_probetab[SDT_ADDR2NDX(regs->ip)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == regs->ip) {
			if (sdt->sdp_ptype == SDTPT_IS_ENABLED)
				regs->ax = 1;
			else {
				struct pt_regs *old_regs =
					this_cpu_core->cpu_dtrace_regs;

				this_cpu_core->cpu_dtrace_regs = regs;

				dtrace_probe(sdt->sdp_id, regs->di, regs->si,
					     regs->dx, regs->cx, regs->r8,
					     regs->r9, 0);

				this_cpu_core->cpu_dtrace_regs = old_regs;
			}

			return DTRACE_INVOP_NOPS;
		}
	}

	return 0;
}

void sdt_provide_probe_arch(struct sdt_probe *sdp, struct module *mp, int idx)
{
	sdp->sdp_patchval = SDT_PATCHVAL;
	sdp->sdp_savedval = *sdp->sdp_patchpoint;
}

int sdt_provide_module_arch(void *arg, struct module *mp)
{
	return 1;
}

void sdt_destroy_module(void *arg, struct module *mp)
{
}

void sdt_enable_arch(struct sdt_probe *sdp, dtrace_id_t id, void *arg)
{
	dtrace_invop_enable(sdp->sdp_patchpoint, sdp->sdp_patchval);
}

void sdt_disable_arch(struct sdt_probe *sdp, dtrace_id_t id, void *arg)
{
	dtrace_invop_disable(sdp->sdp_patchpoint, sdp->sdp_savedval);
}

uint64_t sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	struct pt_regs  *regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		return 0;

	switch (argno) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->cx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}

	ASSERT(argno > 5);

	st = (uint64_t *)regs->sp;
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = st[argno - 6];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return val;
}

int sdt_dev_init_arch(void)
{
	return dtrace_invop_add(sdt_invop);
}

void sdt_dev_exit_arch(void)
{
	dtrace_invop_remove(sdt_invop);
}
