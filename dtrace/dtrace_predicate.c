/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_predicate.c
 * DESCRIPTION:	DTrace - predicate cache implementation
 *
 * Copyright (c) 2010, 2013, Oracle and/or its affiliates. All rights reserved.
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

#include "dtrace.h"

static dtrace_cacheid_t	dtrace_predcache_id = DTRACE_CACHEIDNONE + 1;

struct dtrace_predicate *dtrace_predicate_create(struct dtrace_difo *dp)
{
	struct dtrace_predicate	*pred;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dp->dtdo_refcnt != 0);

	pred = kzalloc(sizeof(struct dtrace_predicate), GFP_KERNEL);
	if (pred == NULL)
		return NULL;

	pred->dtp_difo = dp;
	pred->dtp_refcnt = 1;

	if (!dtrace_difo_cacheable(dp))
		return pred;

	/*
	 * This is only theoretically possible -- we have had 2^32 cacheable
	 * predicates on this machine.  We cannot allow any more predicates to
	 * become cacheable:  as unlikely as it is, there may be a thread
	 * caching a (now stale) predicate cache ID. (N.B.: the temptation is
	 * being successfully resisted to have this cmn_err() "Holy shit -- we
	 * executed this code!")
	 */
	if (dtrace_predcache_id == DTRACE_CACHEIDNONE)
		return pred;

	pred->dtp_cacheid = dtrace_predcache_id++;

	return pred;
}

void dtrace_predicate_hold(struct dtrace_predicate *pred)
{
	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(pred->dtp_difo != NULL && pred->dtp_difo->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	pred->dtp_refcnt++;
}

void dtrace_predicate_release(struct dtrace_predicate *pred,
			      struct dtrace_vstate *vstate)
{
	struct dtrace_difo *dp = pred->dtp_difo;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dp != NULL && dp->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	if (--pred->dtp_refcnt == 0) {
		dtrace_difo_release(dp, vstate);
		kfree(pred);
	}
}
