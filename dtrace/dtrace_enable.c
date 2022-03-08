/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_enable.c
 * DESCRIPTION:	DTrace - probe enabling implementation
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

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dtrace.h"

size_t			dtrace_retain_max = 1024;
struct dtrace_enabling	*dtrace_retained;
dtrace_genid_t		dtrace_retained_gen;

struct dtrace_enabling *dtrace_enabling_create(struct dtrace_vstate *vstate)
{
	struct dtrace_enabling	*enab;

	enab = kzalloc(sizeof(struct dtrace_enabling), GFP_KERNEL);
	if (enab == NULL)
		return NULL;

	enab->dten_vstate = vstate;

	return enab;
}

void dtrace_enabling_add(struct dtrace_enabling *enab,
			 struct dtrace_ecbdesc *ecb)
{
	struct dtrace_ecbdesc	**ndesc;
	size_t			osize, nsize;

	/*
	 * We can't add to enablings after we've enabled them, or after we've
	 * retained them.
	 */
	ASSERT(enab->dten_probegen == 0);
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);

	if (enab->dten_ndesc < enab->dten_maxdesc) {
		enab->dten_desc[enab->dten_ndesc++] = ecb;
		return;
	}

	osize = enab->dten_maxdesc * sizeof(struct dtrace_enabling *);

	if (enab->dten_maxdesc == 0)
		enab->dten_maxdesc = 1;
	else
		enab->dten_maxdesc <<= 1;

	ASSERT(enab->dten_ndesc < enab->dten_maxdesc);

	nsize = enab->dten_maxdesc * sizeof(struct dtrace_enabling *);
	ndesc = vzalloc(nsize);
	memcpy(ndesc, enab->dten_desc, osize);
	vfree(enab->dten_desc);

	enab->dten_desc = ndesc;
	enab->dten_desc[enab->dten_ndesc++] = ecb;
}

static void dtrace_enabling_addlike(struct dtrace_enabling *enab,
				    struct dtrace_ecbdesc *ecb,
				    struct dtrace_probedesc *pd)
{
	struct dtrace_ecbdesc	*new;
	struct dtrace_predicate	*pred;
	struct dtrace_actdesc	*act;

	/*
	 * We're going to create a new ECB description that matches the
	 * specified ECB in every way, but has the specified probe description.
	 */
	new = kzalloc(sizeof(struct dtrace_ecbdesc), GFP_KERNEL);

	pred = ecb->dted_pred.dtpdd_predicate;
	if (pred != NULL)
		dtrace_predicate_hold(pred);

	for (act = ecb->dted_action; act != NULL; act = act->dtad_next)
		dtrace_actdesc_hold(act);

	new->dted_action = ecb->dted_action;
	new->dted_pred = ecb->dted_pred;
	new->dted_probe = *pd;
	new->dted_uarg = ecb->dted_uarg;

	dtrace_enabling_add(enab, new);
}

void dtrace_enabling_dump(struct dtrace_enabling *enab)
{
	int	i;

	for (i = 0; i < enab->dten_ndesc; i++) {
		struct dtrace_probedesc	*desc =
					&enab->dten_desc[i]->dted_probe;

		pr_info("enabling probe %d (%s:%s:%s:%s)",
			i, desc->dtpd_provider, desc->dtpd_mod,
			desc->dtpd_func, desc->dtpd_name);
	}
}

void dtrace_enabling_destroy(struct dtrace_enabling *enab)
{
	int			i;
	struct dtrace_ecbdesc	*ep;
	struct dtrace_vstate	*vstate = enab->dten_vstate;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	for (i = 0; i < enab->dten_ndesc; i++) {
		struct dtrace_actdesc	*act, *next;
		struct dtrace_predicate	*pred;

		ep = enab->dten_desc[i];

		pred = ep->dted_pred.dtpdd_predicate;
		if (pred != NULL)
			dtrace_predicate_release(pred, vstate);

		for (act = ep->dted_action; act != NULL; act = next) {
			next = act->dtad_next;
			dtrace_actdesc_release(act, vstate);
		}

		kfree(ep);
	}

	vfree(enab->dten_desc);

	/*
	 * If this was a retained enabling, decrement the dts_nretained count
	 * and remove it from the dtrace_retained list.
	 */
	if (enab->dten_prev != NULL || enab->dten_next != NULL ||
	    dtrace_retained == enab) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);
		ASSERT(enab->dten_vstate->dtvs_state->dts_nretained > 0);
		enab->dten_vstate->dtvs_state->dts_nretained--;
		dtrace_retained_gen++;
	}

	if (enab->dten_prev == NULL) {
		if (dtrace_retained == enab) {
			dtrace_retained = enab->dten_next;

			if (dtrace_retained != NULL)
				dtrace_retained->dten_prev = NULL;
		}
	} else {
		ASSERT(enab != dtrace_retained);
		ASSERT(dtrace_retained != NULL);
		enab->dten_prev->dten_next = enab->dten_next;
	}

	if (enab->dten_next != NULL) {
		ASSERT(dtrace_retained != NULL);
		enab->dten_next->dten_prev = enab->dten_prev;
	}

	kfree(enab);
}

int dtrace_enabling_retain(struct dtrace_enabling *enab)
{
	struct dtrace_state	*state;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);
	ASSERT(enab->dten_vstate != NULL);

	state = enab->dten_vstate->dtvs_state;
	ASSERT(state != NULL);

	/*
	 * We only allow each state to retain dtrace_retain_max enablings.
	 */
	if (state->dts_nretained >= dtrace_retain_max)
		return -ENOSPC;

	state->dts_nretained++;
	dtrace_retained_gen++;

	if (dtrace_retained == NULL) {
		dtrace_retained = enab;
		return 0;
	}

	enab->dten_next = dtrace_retained;
	dtrace_retained->dten_prev = enab;
	dtrace_retained = enab;

	return 0;
}

int dtrace_enabling_replicate(struct dtrace_state *state,
			      struct dtrace_probedesc *match,
			      struct dtrace_probedesc *create)
{
	struct dtrace_enabling	*new, *enab;
	int			found = 0, err = -ENOENT;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(strlen(match->dtpd_provider) < DTRACE_PROVNAMELEN);
	ASSERT(strlen(match->dtpd_mod) < DTRACE_MODNAMELEN);
	ASSERT(strlen(match->dtpd_func) < DTRACE_FUNCNAMELEN);
	ASSERT(strlen(match->dtpd_name) < DTRACE_NAMELEN);

	new = dtrace_enabling_create(&state->dts_vstate);
	if (new == NULL)
		return -ENOMEM;

	/*
	 * Iterate over all retained enablings, looking for enablings that
	 * match the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		int	i;

		/*
		 * dtvs_state can only be NULL for helper enablings -- and
		 * helper enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * Now iterate over each probe description; we're looking for
		 * an exact match to the specified probe description.
		 */
		for (i = 0; i < enab->dten_ndesc; i++) {
			struct dtrace_ecbdesc	*ep = enab->dten_desc[i];
			struct dtrace_probedesc	*pd = &ep->dted_probe;

			if (strcmp(pd->dtpd_provider, match->dtpd_provider))
				continue;

			if (strcmp(pd->dtpd_mod, match->dtpd_mod))
				continue;

			if (strcmp(pd->dtpd_func, match->dtpd_func))
				continue;

			if (strcmp(pd->dtpd_name, match->dtpd_name))
				continue;

			/*
			 * We have a winning probe!  Add it to our growing
			 * enabling.
			 */
			found = 1;
			dtrace_enabling_addlike(new, ep, create);
		}
	}

	if (!found || (err = dtrace_enabling_retain(new)) != 0) {
		dtrace_enabling_destroy(new);
		return err;
	}

	return 0;
}

void dtrace_enabling_retract(struct dtrace_state *state)
{
	struct dtrace_enabling	*enab, *next;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	/*
	 * Iterate over all retained enablings, destroy the enablings retained
	 * for the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = next) {
		next = enab->dten_next;

		/*
		 * dtvs_state can only be NULL for helper enablings, and helper
		 * enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state == state) {
			ASSERT(state->dts_nretained > 0);
			dtrace_enabling_destroy(enab);
		}
	}

	ASSERT(state->dts_nretained == 0);
}

int dtrace_enabling_match(struct dtrace_enabling *enab, int *nmatched)
{
	int	i;
	int	total_matched = 0, matched = 0;

	for (i = 0; i < enab->dten_ndesc; i++) {
		struct dtrace_ecbdesc	*ep = enab->dten_desc[i];

		enab->dten_current = ep;
		enab->dten_error = 0;

		dt_dbg_enable("  Matching enabling %p[%d] for %s:%s:%s:%s\n",
			      enab, i, ep->dted_probe.dtpd_provider,
			      ep->dted_probe.dtpd_mod,
			      ep->dted_probe.dtpd_func,
			      ep->dted_probe.dtpd_name);

		matched = dtrace_probe_enable(&ep->dted_probe, enab);
		if (matched < 0) {
			dt_dbg_enable("  Matching enabling %p[%d] failed: "
				      "busy\n", enab, i);
			return -EBUSY;
		}

		dt_dbg_enable("  Matching enabling %p[%d] found %d matches.\n",
			      enab, i, matched);

		total_matched += matched;

		if (enab->dten_error != 0) {
			if (nmatched == NULL)
				pr_warn("%s error on %p: %d\n", __func__,
					(void *)ep, enab->dten_error);

			return enab->dten_error;
		}
	}

	enab->dten_probegen = dtrace_probegen;
	if (nmatched != NULL)
		*nmatched = total_matched;

	return 0;
}

void dtrace_enabling_matchall(void)
{
	struct dtrace_enabling	*enab;

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);

	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next)
		(void) dtrace_enabling_match(enab, NULL);

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&cpu_lock);
}

/*
 * If an enabling is to be enabled without having matched probes (that is, if
 * dtrace_state_go() is to be called on the underlying dtrace_state_t), the
 * enabling must be _primed_ by creating an ECB for every ECB description.
 * This must be done to assure that we know the number of speculations, the
 * number of aggregations, the minimum buffer size needed, etc. before we
 * transition out of DTRACE_ACTIVITY_INACTIVE.  To do this without actually
 * enabling any probes, we create ECBs for every ECB description, but with a
 * NULL probe -- which is exactly what this function does.
 */
void dtrace_enabling_prime(struct dtrace_state *state)
{
	struct dtrace_enabling	*enab;
	int			i;

	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * We don't want to prime an enabling more than once, lest
		 * we allow a malicious user to induce resource exhaustion.
		 * (The ECBs that result from priming an enabling aren't
		 * leaked -- but they also aren't deallocated until the
		 * consumer state is destroyed.)
		 */
		if (enab->dten_primed)
			continue;

		for (i = 0; i < enab->dten_ndesc; i++) {
			enab->dten_current = enab->dten_desc[i];
			dtrace_probe_enable(NULL, enab);
		}

		enab->dten_primed = 1;
	}
}

void dtrace_enabling_provide(struct dtrace_provider *prv)
{
	int		all = 0;
	dtrace_genid_t	gen;

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		struct dtrace_enabling	*enab;
		void			*parg = prv->dtpv_arg;

retry:
		gen = dtrace_retained_gen;
		for (enab = dtrace_retained; enab != NULL;
		     enab = enab->dten_next) {
			int	i;

			for (i = 0; i < enab->dten_ndesc; i++) {
				struct dtrace_probedesc	desc;

				desc = enab->dten_desc[i]->dted_probe;
				mutex_unlock(&dtrace_lock);
				prv->dtpv_pops.dtps_provide(parg, &desc);
				mutex_lock(&dtrace_lock);

				if (gen != dtrace_retained_gen)
					goto retry;
			}
		}
	} while (all && (prv = prv->dtpv_next) != NULL);

	mutex_unlock(&dtrace_lock);
	dtrace_probe_provide(NULL, all ? NULL : prv);
	mutex_lock(&dtrace_lock);
}
