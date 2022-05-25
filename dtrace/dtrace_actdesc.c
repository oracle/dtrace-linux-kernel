/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_actdesc.c
 * DESCRIPTION:	DTrace - action implementation
 *
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dtrace.h"

struct dtrace_actdesc *dtrace_actdesc_create(dtrace_actkind_t kind,
                                             uint32_t ntuple,
                                             uint64_t uarg, uint64_t arg)
{
	struct dtrace_actdesc	*act;

#ifdef FIXME
	ASSERT(!DTRACEACT_ISPRINTFLIKE(kind) ||
	       (arg != 0 && (uintptr_t)arg >= KERNELBASE) ||
	       (arg == 0 && kind == DTRACEACT_PRINTA));
#else
	ASSERT(!DTRACEACT_ISPRINTFLIKE(kind) ||
	       (arg != 0) ||
	       (arg == 0 && kind == DTRACEACT_PRINTA));
#endif

	act = kzalloc(sizeof(struct dtrace_actdesc), GFP_KERNEL);
	if (act == NULL)
		return NULL;

	act->dtad_kind = kind;
	act->dtad_ntuple = ntuple;
	act->dtad_uarg = uarg;
	act->dtad_arg = arg;
	act->dtad_refcnt = 1;

	return act;
}

void dtrace_actdesc_hold(struct dtrace_actdesc *act)
{
	ASSERT(act->dtad_refcnt >= 1);

	act->dtad_refcnt++;
}

void dtrace_actdesc_release(struct dtrace_actdesc *act,
			    struct dtrace_vstate *vstate)
{
	dtrace_actkind_t	kind = act->dtad_kind;
	struct dtrace_difo	*dp;

	ASSERT(act->dtad_refcnt >= 1);

	if (--act->dtad_refcnt != 0)
		return;

	dp = act->dtad_difo;
	if (dp != NULL)
		dtrace_difo_release(dp, vstate);

	if (DTRACEACT_ISPRINTFLIKE(kind)) {
		char	*str = (char *)(uintptr_t)act->dtad_arg;

#ifdef FIXME
		ASSERT((str != NULL && (uintptr_t)str >= KERNELBASE) ||
		       (str == NULL && act->dtad_kind == DTRACEACT_PRINTA));
#else
		ASSERT((str != NULL) ||
		       (str == NULL && act->dtad_kind == DTRACEACT_PRINTA));
#endif

		if (str != NULL)
			vfree(str);
	}

	kfree(act);
}
