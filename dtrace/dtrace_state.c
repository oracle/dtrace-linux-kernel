/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_state.c
 * DESCRIPTION:	DTrace - consumer state implementation
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

#include <linux/cyclic.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <asm/cmpxchg.h>

#include "dtrace.h"

int			dtrace_destructive_disallow = 0;
dtrace_optval_t		dtrace_nspec_default = 1;
dtrace_optval_t		dtrace_specsize_default = 32 * 1024;
dtrace_optval_t		dtrace_dstate_defsize = 1 * 1024 * 1024;
size_t			dtrace_strsize_default = 256;
dtrace_optval_t		dtrace_stackframes_default = 20;
dtrace_optval_t		dtrace_ustackframes_default = 100;
dtrace_optval_t		dtrace_cleanrate_default = 9900990;
dtrace_optval_t		dtrace_cleanrate_min = 20000;
dtrace_optval_t		dtrace_cleanrate_max = (uint64_t)60 * NANOSEC;
dtrace_optval_t		dtrace_aggrate_default = NANOSEC;
dtrace_optval_t		dtrace_switchrate_default = NANOSEC;
dtrace_optval_t		dtrace_statusrate_default = NANOSEC;
dtrace_optval_t		dtrace_statusrate_max = (uint64_t)10 * NANOSEC;
dtrace_optval_t		dtrace_jstackframes_default = 50;
dtrace_optval_t		dtrace_jstackstrsize_default = 512;
ktime_t			dtrace_deadman_interval = KTIME_INIT(1, 0);
ktime_t			dtrace_deadman_timeout = KTIME_INIT(10, 0);
ktime_t			dtrace_deadman_user = KTIME_INIT(30, 0);

			/* Sampling before counting */
uint64_t		dtrace_sync_sample_count = 100;

dtrace_id_t		dtrace_probeid_begin;
dtrace_id_t		dtrace_probeid_end;
dtrace_id_t		dtrace_probeid_error;

struct dtrace_dynvar	dtrace_dynhash_sink;

#define DTRACE_DYNHASH_FREE		0
#define DTRACE_DYNHASH_SINK		1
#define DTRACE_DYNHASH_VALID		2

#define DTRACE_DYNVAR_CHUNKSIZE		256

static void dtrace_dynvar_clean(struct dtrace_dstate *dstate)
{
	struct dtrace_dynvar		*dirty;
	struct dtrace_dstate_percpu	*dcpu;
	int				i, work = 0;

	for (i = 0; i < NR_CPUS; i++) {
		dcpu = &dstate->dtds_percpu[i];

		ASSERT(dcpu->dtdsc_rinsing == NULL);

		/*
		 * If the dirty list is NULL, there is no dirty work to do.
		 */
		if (dcpu->dtdsc_dirty == NULL)
			continue;

		/*
		 * If the clean list is non-NULL, then we're not going to do
		 * any work for this CPU -- it means that there has not been
		 * a dtrace_dynvar() allocation on this CPU (or from this CPU)
		 * since the last time we cleaned house.
		 */
		if (dcpu->dtdsc_clean != NULL)
			continue;

		work = 1;

		/*
		 * Atomically move the dirty list aside.
		 */
		do {
			dirty = dcpu->dtdsc_dirty;

			/*
			 * Before we zap the dirty list, set the rinsing list.
			 * (This allows for a potential assertion in
			 * dtrace_dynvar():  if a free dynamic variable appears
			 * on a hash chain, either the dirty list or the
			 * rinsing list for some CPU must be non-NULL.)
			 */
			dcpu->dtdsc_rinsing = dirty;
			dtrace_membar_producer();
		} while (cmpxchg(&dcpu->dtdsc_dirty, dirty, NULL) != dirty);
	}

	/*
	 * No work to do; return.
	 */
	if (!work)
		return;

	dtrace_sync();

	for (i = 0; i < NR_CPUS; i++) {
		dcpu = &dstate->dtds_percpu[i];

		if (dcpu->dtdsc_rinsing == NULL)
			continue;

		/*
		 * We are now guaranteed that no hash chain contains a pointer
		 * into this dirty list; we can make it clean.
		 */
		ASSERT(dcpu->dtdsc_clean == NULL);
		dcpu->dtdsc_clean = dcpu->dtdsc_rinsing;
		dcpu->dtdsc_rinsing = NULL;
	}

	/*
	 * Before we actually set the state to be DTRACE_DSTATE_CLEAN, make
	 * sure that all CPUs have seen all of the dtdsc_clean pointers.
	 * This prevents a race whereby a CPU incorrectly decides that
	 * the state should be something other than DTRACE_DSTATE_CLEAN
	 * after dtrace_dynvar_clean() has completed.
	 */
	dtrace_sync();

	dstate->dtds_state = DTRACE_DSTATE_CLEAN;
}

int dtrace_dstate_init(struct dtrace_dstate *dstate, size_t size)
{
	size_t		hashsize, maxper, min,
			chunksize = dstate->dtds_chunksize;
	void		*base, *percpu;
	uintptr_t	limit;
	struct dtrace_dynvar *dvar, *next, *start;
	int		i;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dstate->dtds_base == NULL && dstate->dtds_percpu == NULL);

	memset(dstate, 0, sizeof(struct dtrace_dstate));

	dstate->dtds_chunksize = chunksize;
	if (dstate->dtds_chunksize == 0)
		dstate->dtds_chunksize = DTRACE_DYNVAR_CHUNKSIZE;

	min = dstate->dtds_chunksize + sizeof(struct dtrace_dynhash);
	if (size < min)
		size = min;

	base = dtrace_vzalloc_try(size);
	if (base == NULL)
		return -ENOMEM;
	percpu = kmem_cache_alloc(dtrace_state_cachep, GFP_KERNEL);
	if (percpu == NULL) {
		vfree(base);
		return -ENOMEM;
	}

	dstate->dtds_size = size;
	dstate->dtds_base = base;
	dstate->dtds_percpu = percpu;
	memset(dstate->dtds_percpu, 0,
	       NR_CPUS * sizeof(struct dtrace_dstate_percpu));

	hashsize = size /
		(dstate->dtds_chunksize + sizeof(struct dtrace_dynhash));

	if (hashsize != 1 && (hashsize & 1))
		hashsize--;

	dstate->dtds_hashsize = hashsize;
	dstate->dtds_hash = dstate->dtds_base;

	/*
	 * Set all of our hash buckets to point to the single sink, and (if
	 * it hasn't already been set), set the sink's hash value to be the
	 * sink sentinel value.  The sink is needed for dynamic variable
	 * lookups to know that they have iterated over an entire, valid hash
	 * chain.
	 */
	for (i = 0; i < hashsize; i++)
		dstate->dtds_hash[i].dtdh_chain = &dtrace_dynhash_sink;

	if (dtrace_dynhash_sink.dtdv_hashval != DTRACE_DYNHASH_SINK)
		dtrace_dynhash_sink.dtdv_hashval = DTRACE_DYNHASH_SINK;

	/*
	 * Determine number of active CPUs.  Divide free list evenly among
	 * active CPUs.
	 */
	start = (struct dtrace_dynvar *)((uintptr_t)base +
				    hashsize * sizeof(struct dtrace_dynhash));
	limit = (uintptr_t)base + size;

	maxper = (limit - (uintptr_t)start) / NR_CPUS;
	maxper = (maxper / dstate->dtds_chunksize) * dstate->dtds_chunksize;

	for (i = 0; i < NR_CPUS; i++) {
		dstate->dtds_percpu[i].dtdsc_free = dvar = start;

		/*
		 * If we don't even have enough chunks to make it once through
		 * NCPUs, we're just going to allocate everything to the first
		 * CPU.  And if we're on the last CPU, we're going to allocate
		 * whatever is left over.  In either case, we set the limit to
		 * be the limit of the dynamic variable space.
		 */
		if (maxper == 0 || i == NR_CPUS - 1) {
			limit = (uintptr_t)base + size;
			start = NULL;
		} else {
			limit = (uintptr_t)start + maxper;
			start = (struct dtrace_dynvar *)limit;
		}

		ASSERT(limit <= (uintptr_t)base + size);

		for (;;) {
			next = (struct dtrace_dynvar *)((uintptr_t)dvar +
						   dstate->dtds_chunksize);

			if ((uintptr_t)next + dstate->dtds_chunksize >= limit)
				break;

			dvar->dtdv_next = next;
			dvar = next;
		}

		if (maxper == 0)
			break;
	}

	return 0;
}

void dtrace_dstate_fini(struct dtrace_dstate *dstate)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (dstate->dtds_base == NULL)
		return;

	vfree(dstate->dtds_base);
	kmem_cache_free(dtrace_state_cachep, dstate->dtds_percpu);
}

void dtrace_vstate_fini(struct dtrace_vstate *vstate)
{
	/*
	 * If only there was a logical XOR operator...
	 */
	ASSERT((vstate->dtvs_nglobals == 0) ^ (vstate->dtvs_globals != NULL));

	if (vstate->dtvs_nglobals > 0)
		vfree(vstate->dtvs_globals);

	if (vstate->dtvs_ntlocals > 0)
		vfree(vstate->dtvs_tlocals);

	ASSERT((vstate->dtvs_nlocals == 0) ^ (vstate->dtvs_locals != NULL));

	if (vstate->dtvs_nlocals > 0)
		vfree(vstate->dtvs_locals);
}

static void dtrace_state_clean(struct dtrace_state *state)
{
	dtrace_optval_t		*opt = state->dts_options;

	if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE &&
	    state->dts_activity != DTRACE_ACTIVITY_DRAINING)
		return;

	dtrace_dynvar_clean(&state->dts_vstate.dtvs_dynvars);
	dtrace_speculation_clean(state);

	cyclic_reprogram(state->dts_cleaner, ns_to_ktime(
						opt[DTRACEOPT_CLEANRATE]));
}

static void dtrace_state_deadman(struct dtrace_state *state)
{
	ktime_t			now;

	dtrace_sync();

	now = dtrace_gethrtime();
	if (state != dtrace_anon.dta_state &&
	    ktime_ge(ktime_sub(now, state->dts_laststatus),
		     dtrace_deadman_user))
		return;

	/*
	 * We must be sure that dts_alive never appears to be less than the
	 * value upon entry to dtrace_state_deadman(), and because we lack a
	 * dtrace_cas64(), we cannot store to it atomically.  We thus instead
	 * store KTIME_MAX to it, followed by a memory barrier, followed by
	 * the new value.  This assures that dts_alive never appears to be
	 * less than its true value, regardless of the order in which the
	 * stores to the underlying storage are issued.
	 */
	state->dts_alive = ktime_set(KTIME_SEC_MAX, 0);
	dtrace_membar_producer();
	state->dts_alive = now;
}

struct dtrace_state *dtrace_state_create(struct file *file)
{
	struct dtrace_state *state;
	dtrace_optval_t	    *opt;
	int                 bufsize = NR_CPUS * sizeof(struct dtrace_buffer), i;
#ifdef FIXME
	const struct cred   *cr = file->f_cred;
#endif
	dtrace_aggid_t aggid;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&dtrace_lock));

	state = kzalloc(sizeof(struct dtrace_state), GFP_KERNEL);
	if (state == NULL)
		return NULL;

	state->dts_epid = DTRACE_EPIDNONE + 1;
	state->dts_buffer = vzalloc(bufsize);
	if (state->dts_buffer == NULL) {
		kfree(state);
		return NULL;
	}

	state->dts_aggbuffer = vzalloc(bufsize);
	if (state->dts_aggbuffer == NULL) {
		vfree(state->dts_buffer);
		kfree(state);
		return NULL;
	}

	idr_init(&state->dts_agg_idr);
	state->dts_naggs = 0;
	state->dts_cleaner = 0;
	state->dts_deadman = 0;
	state->dts_vstate.dtvs_state = state;

	/*
	 * Create a first entry in the aggregation IDR, so that ID 0 is used as
	 * that gets used as meaning 'none'.
	 */
	idr_preload(GFP_KERNEL);
	aggid = idr_alloc_cyclic(&state->dts_agg_idr, NULL, 0, 0, GFP_NOWAIT);
	idr_preload_end();

	ASSERT(aggid == 0);

	for (i = 0; i < DTRACEOPT_MAX; i++)
		state->dts_options[i] = DTRACEOPT_UNSET;

	/*
	 * Set the default options.
	 */
	opt = state->dts_options;
	opt[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_SWITCH;
	opt[DTRACEOPT_BUFRESIZE] = DTRACEOPT_BUFRESIZE_AUTO;
	opt[DTRACEOPT_NSPEC] = dtrace_nspec_default;
	opt[DTRACEOPT_SPECSIZE] = dtrace_specsize_default;
	opt[DTRACEOPT_CPU] = (dtrace_optval_t)DTRACE_CPUALL;
	opt[DTRACEOPT_STRSIZE] = dtrace_strsize_default;
	opt[DTRACEOPT_STACKFRAMES] = dtrace_stackframes_default;
	opt[DTRACEOPT_USTACKFRAMES] = dtrace_ustackframes_default;
	opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_default;
	opt[DTRACEOPT_AGGRATE] = dtrace_aggrate_default;
	opt[DTRACEOPT_SWITCHRATE] = dtrace_switchrate_default;
	opt[DTRACEOPT_STATUSRATE] = dtrace_statusrate_default;
	opt[DTRACEOPT_JSTACKFRAMES] = dtrace_jstackframes_default;
	opt[DTRACEOPT_JSTACKSTRSIZE] = dtrace_jstackstrsize_default;

	state->dts_activity = DTRACE_ACTIVITY_INACTIVE;

#ifdef FIXME
	/*
	 * Set probe visibility and destructiveness based on user credential
	 * information.  For actual anonymous tracing or if all privileges are
	 * set, checks are bypassed.
	 */
	if (cr == NULL ||
	    PRIV_POLICY_ONLY(cr, PRIV_ALL, FALSE)) {
		state->dts_cred.dcr_visible = DTRACE_CRV_ALL;
		state->dts_cred.dcr_action = DTRACE_CRA_ALL;
	} else {
		state->dts_cred.dcr_cred = get_cred(cr);

		/*
		 * CRA_PROC means "we have *some* privilege for dtrace" and
		 * it unlocks the use of variables like pid, etc.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_USER, FALSE) ||
		    PRIV_POLICY_ONLY(cr, PRIV_DTRACE_PROC, FALSE))
			state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

		/*
		 * The DTRACE_USER privilege allows the use of syscall and
		 * profile providers.  If the user also has PROC_OWNER, we
		 * extend the scope to include additional visibility and
		 * destructive power.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_USER, FALSE)) {
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, FALSE))
				state->dts_cred.dcr_visible |=
					DTRACE_CRV_ALLPROC;

			state->dts_cred.dcr_action |=
					DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;
		}

		/*
		 * Holding the DTRACE_KERNEL privilege also implies that
		 * the user has the DTRACE_USER privilege from a visibility
		 * perspective.  But without further privileges, some
		 * destructive actions are not available.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_KERNEL, FALSE)) {
			/*
			 * Make all probes in all zones visible.  However,
			 * this doesn't mean that all actions become available
			 * to all zones.
			 */
			state->dts_cred.dcr_visible |= DTRACE_CRV_KERNEL |
						       DTRACE_CRV_ALLPROC;
			state->dts_cred.dcr_action |= DTRACE_CRA_KERNEL |
						      DTRACE_CRA_PROC;

			/*
			 * Holding PROC_OWNER means that destructive actions
			 * are allowed.
			 */
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, FALSE))
				state->dts_cred.dcr_action |=
					DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;
		}

		/*
		 * Holding the DTRACE_PROC privilege gives control over the
		 * fasttrap and pid providers.  We need to grant wider
		 * destructive privileges in the event that the user has
		 * PROC_OWNER .
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_PROC, FALSE)) {
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, FALSE))
				state->dts_cred.dcr_action |=
					DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;
		}
	}
#else
	state->dts_cred.dcr_visible = DTRACE_CRV_ALLPROC | DTRACE_CRV_KERNEL;
	state->dts_cred.dcr_action = DTRACE_CRA_ALL;
#endif

	return state;
}

static int dtrace_state_buffer(struct dtrace_state *state,
			       struct dtrace_buffer *buf, int which)
{
	dtrace_optval_t	*opt = state->dts_options, size;
	processorid_t	cpu = DTRACE_CPUALL;
	int		flags = 0, rval;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(which < DTRACEOPT_MAX);
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_INACTIVE ||
	       (state == dtrace_anon.dta_state &&
	       state->dts_activity == DTRACE_ACTIVITY_ACTIVE));

	if (opt[which] == DTRACEOPT_UNSET || opt[which] == 0)
		return 0;

	if (opt[DTRACEOPT_CPU] != DTRACEOPT_UNSET)
		cpu = opt[DTRACEOPT_CPU];

	if (which == DTRACEOPT_SPECSIZE)
		flags |= DTRACEBUF_NOSWITCH;

	if (which == DTRACEOPT_BUFSIZE) {
		if (opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_RING)
			flags |= DTRACEBUF_RING;

		if (opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_FILL)
			flags |= DTRACEBUF_FILL;

		if (state != dtrace_anon.dta_state ||
		    state->dts_activity != DTRACE_ACTIVITY_ACTIVE)
			flags |= DTRACEBUF_INACTIVE;
	}

	for (size = opt[which]; size >= sizeof(uint64_t); size >>= 1) {
		/*
		 * The size must be 8-byte aligned.  If the size is not 8-byte
		 * aligned, drop it down by the difference.
		 */
		if (size & (sizeof(uint64_t) - 1))
			size -= size & (sizeof(uint64_t) - 1);

		if (size < state->dts_reserve) {
			/*
			 * Buffers always must be large enough to accommodate
			 * their prereserved space.  We return -E2BIG instead
			 * of ENOMEM in this case to allow for user-level
			 * software to differentiate the cases.
			 */
			return -E2BIG;
		}

		rval = dtrace_buffer_alloc(buf, size, flags, cpu);
		if (rval != -ENOMEM) {
			opt[which] = size;
			return rval;
		}

		if (opt[DTRACEOPT_BUFRESIZE] == DTRACEOPT_BUFRESIZE_MANUAL)
			return rval;
	}

	return -ENOMEM;
}

static int dtrace_state_buffers(struct dtrace_state *state)
{
	struct dtrace_speculation	*spec = state->dts_speculations;
	int				rval, i;

	rval = dtrace_state_buffer(state, state->dts_buffer, DTRACEOPT_BUFSIZE);
	if (rval != 0)
		return rval;

	rval = dtrace_state_buffer(state, state->dts_aggbuffer,
				   DTRACEOPT_AGGSIZE);
	if (rval != 0)
		return rval;

	for (i = 0; i < state->dts_nspeculations; i++) {
		rval = dtrace_state_buffer(state, spec[i].dtsp_buffer,
					   DTRACEOPT_SPECSIZE);
		if (rval != 0)
			return rval;
	}

	return 0;
}

static void dtrace_begin_probe(struct dtrace_state *state)
{
	processorid_t		cpuid;

	preempt_disable();
	cpuid = smp_processor_id();

	ASSERT(state->dts_buffer[cpuid].dtb_flags & DTRACEBUF_INACTIVE);
	state->dts_buffer[cpuid].dtb_flags &= ~DTRACEBUF_INACTIVE;

	dtrace_probe(dtrace_probeid_begin, (uint64_t)(uintptr_t)state, 0, 0, 0,
		     0, 0, 0);

	/*
	 * We may have had an exit action from a BEGIN probe; only change our
	 * state to ACTIVE if we're still in WARMUP.
	 */
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_WARMUP ||
	       state->dts_activity == DTRACE_ACTIVITY_DRAINING);

	if (state->dts_activity == DTRACE_ACTIVITY_WARMUP)
		state->dts_activity = DTRACE_ACTIVITY_ACTIVE;

	preempt_enable();
	dtrace_membar_enter();
}

static void dtrace_state_prereserve(struct dtrace_state *state)
{
	struct dtrace_ecb	*ecb;
	struct dtrace_probe	*probe;

	state->dts_reserve = 0;

	if (state->dts_options[DTRACEOPT_BUFPOLICY] != DTRACEOPT_BUFPOLICY_FILL)
		return;

	/*
	 * If our buffer policy is a "fill" buffer policy, we need to set the
	 * prereserved space to be the space required by the END probes.
	 */
	probe = dtrace_probe_lookup_id(dtrace_probeid_end);
	ASSERT(probe != NULL);

	for (ecb = probe->dtpr_ecb; ecb != NULL; ecb = ecb->dte_next) {
		if (ecb->dte_state != state)
			continue;

		state->dts_reserve += ecb->dte_needed + ecb->dte_alignment;
	}
}

int dtrace_state_go(struct dtrace_state *state, processorid_t *cpu)
{
	dtrace_optval_t           *opt = state->dts_options, sz, nspec;
	struct dtrace_speculation *spec;
	struct dtrace_buffer	  *buf;
	struct cyc_handler	  hdlr;
	struct cyc_time		  when;
	processorid_t		  cpuid;
	int rval = 0, i, bufsize = NR_CPUS * sizeof(struct dtrace_buffer);

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);
	preempt_disable();

	if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE) {
		rval = -EBUSY;
		goto out;
	}

	/*
	 * Before we can perform any checks, we must prime all of the
	 * retained enablings that correspond to this state.
	 */
	dtrace_enabling_prime(state);

	if (state->dts_destructive && !state->dts_cred.dcr_destructive) {
		rval = -EACCES;
		goto out;
	}

	dtrace_state_prereserve(state);

	/*
	 * If a cpu has been selected check if its value is valid and
	 * the cpu is online.
	 */
	cpuid = opt[DTRACEOPT_CPU];
	if (cpuid != DTRACE_CPUALL &&
	   (cpuid < 0 || cpuid >= NR_CPUS || !cpu_online(cpuid))) {
		rval = -ENXIO;
		goto out;
	}

	/*
	 * Now we want to do is try to allocate our speculations.
	 * We do not automatically resize the number of speculations; if
	 * this fails, we will fail the operation.
	 */
	nspec = opt[DTRACEOPT_NSPEC];
	ASSERT(nspec != DTRACEOPT_UNSET);

	if (nspec > INT_MAX) {
		rval = -ENOMEM;
		goto out;
	}

	spec = vzalloc(nspec * sizeof(struct dtrace_speculation));
	if (spec == NULL) {
		rval = -ENOMEM;
		goto out;
	}

	state->dts_speculations = spec;
	state->dts_nspeculations = (int)nspec;

	for (i = 0; i < nspec; i++) {
		buf = vzalloc(bufsize);
		if (buf == NULL) {
			rval = -ENOMEM;
			goto err;
		}

		spec[i].dtsp_buffer = buf;
	}

	if (opt[DTRACEOPT_GRABANON] != DTRACEOPT_UNSET) {
		if (dtrace_anon.dta_state == NULL) {
			rval = -ENOENT;
			goto out;
		}

		if (state->dts_necbs != 0) {
			rval = -EALREADY;
			goto out;
		}

		state->dts_anon = dtrace_anon_grab();
		ASSERT(state->dts_anon != NULL);
		state = state->dts_anon;

		/*
		 * We want "grabanon" to be set in the grabbed state, so we'll
		 * copy that option value from the grabbing state into the
		 * grabbed state.
		 */
		state->dts_options[DTRACEOPT_GRABANON] =
						opt[DTRACEOPT_GRABANON];

		*cpu = dtrace_anon.dta_beganon;

		/*
		 * If the anonymous state is active (as it almost certainly
		 * is if the anonymous enabling ultimately matched anything),
		 * we don't allow any further option processing -- but we
		 * don't return failure.
		 */
		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE)
			goto out;
	}

	if (opt[DTRACEOPT_AGGSIZE] != DTRACEOPT_UNSET &&
	    opt[DTRACEOPT_AGGSIZE] != 0) {
		if (state->dts_naggs == 0) {
			/*
			 * We're not going to create an aggregation buffer
			 * because we don't have any ECBs that contain
			 * aggregations -- set this option to 0.
			 */
			opt[DTRACEOPT_AGGSIZE] = 0;
		} else {
			/*
			 * If we have an aggregation buffer, we must also have
			 * a buffer to use as scratch.
			 */
			if (opt[DTRACEOPT_BUFSIZE] == DTRACEOPT_UNSET ||
			    opt[DTRACEOPT_BUFSIZE] < state->dts_needed)
				opt[DTRACEOPT_BUFSIZE] = state->dts_needed;
		}
	}

	if (opt[DTRACEOPT_SPECSIZE] != DTRACEOPT_UNSET &&
	    opt[DTRACEOPT_SPECSIZE] != 0) {
		/*
		 * We are not going to create speculation buffers if we do not
		 * have any ECBs that actually speculate.
		 */
		if (!state->dts_speculates)
			opt[DTRACEOPT_SPECSIZE] = 0;
	}

	/*
	 * The bare minimum size for any buffer that we're actually going to
	 * do anything to is sizeof (uint64_t).
	 */
	sz = sizeof(uint64_t);

	if ((state->dts_needed != 0 && opt[DTRACEOPT_BUFSIZE] < sz) ||
	    (state->dts_speculates && opt[DTRACEOPT_SPECSIZE] < sz) ||
	    (state->dts_naggs != 0 && opt[DTRACEOPT_AGGSIZE] < sz)) {
		/*
		 * A buffer size has been explicitly set to 0 (or to a size
		 * that will be adjusted to 0) and we need the space -- we
		 * need to return failure.  We return -ENOSPC to differentiate
		 * it from failing to allocate a buffer due to failure to meet
		 * the reserve (for which we return -E2BIG).
		 */
		rval = -ENOSPC;
		goto out;
	}

	rval = dtrace_state_buffers(state);
	if (rval != 0)
		goto err;

	sz = opt[DTRACEOPT_DYNVARSIZE];
	if (sz == DTRACEOPT_UNSET)
		sz = dtrace_dstate_defsize;

	do {
		rval = dtrace_dstate_init(&state->dts_vstate.dtvs_dynvars, sz);

		if (rval == 0)
			break;

		if (opt[DTRACEOPT_BUFRESIZE] == DTRACEOPT_BUFRESIZE_MANUAL)
			goto err;
	} while (sz >>= 1);

	opt[DTRACEOPT_DYNVARSIZE] = sz;

	if (rval != 0)
		goto err;

	if (opt[DTRACEOPT_STATUSRATE] > dtrace_statusrate_max)
		opt[DTRACEOPT_STATUSRATE] = dtrace_statusrate_max;

	if (opt[DTRACEOPT_CLEANRATE] == 0)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_max;

	if (opt[DTRACEOPT_CLEANRATE] < dtrace_cleanrate_min)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_min;

	if (opt[DTRACEOPT_CLEANRATE] > dtrace_cleanrate_max)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_max;

	hdlr.cyh_func = (cyc_func_t)dtrace_state_clean;
	hdlr.cyh_arg = (uintptr_t)state;
	hdlr.cyh_level = CY_LOW_LEVEL;

	when.cyt_when = ktime_set(0, 0);
	when.cyt_interval = CY_INTERVAL_INF;

	state->dts_cleaner = cyclic_add(&hdlr, &when);
	cyclic_reprogram(state->dts_cleaner, ns_to_ktime(
						opt[DTRACEOPT_CLEANRATE]));

	hdlr.cyh_func = (cyc_func_t)dtrace_state_deadman;
	hdlr.cyh_arg = (uintptr_t)state;
	hdlr.cyh_level = CY_LOW_LEVEL;

	when.cyt_when = ktime_set(0, 0);
	when.cyt_interval = dtrace_deadman_interval;

	state->dts_alive = state->dts_laststatus = dtrace_gethrtime();
	state->dts_deadman = cyclic_add(&hdlr, &when);

	state->dts_activity = DTRACE_ACTIVITY_WARMUP;

	/*
	 * Issue xcall even when the BEGIN probe fires on current CPU.  The
	 * underlying implementation of SMP will turn it into direct function
	 * call.  It is not allowed to turn off interrupts so we need to pick 
	 * a cpu first and then xcall it.  This way a begin probe will always
	 * fire on the expected cpu.
	 */
	*cpu = (cpuid == DTRACE_CPUALL) ? smp_processor_id() : cpuid;
	dtrace_xcall(*cpu, (dtrace_xcall_t)dtrace_begin_probe, state);

	/*
	 * Regardless of whether or not now we're in ACTIVE or DRAINING, we
	 * want each CPU to transition its principal buffer out of the
	 * INACTIVE state.  Doing this assures that no CPU will suddenly begin
	 * processing an ECB halfway down a probe's ECB chain; all CPUs will
	 * atomically transition from processing none of a state's ECBs to
	 * processing all of them.
	 */
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)dtrace_buffer_activate,
		     state);
	goto out;

err:
	dtrace_buffer_free(state->dts_buffer);
	dtrace_buffer_free(state->dts_aggbuffer);

	nspec = state->dts_nspeculations;
	if (nspec == 0) {
		ASSERT(state->dts_speculations == NULL);
		goto out;
	}

	spec = state->dts_speculations;
	ASSERT(spec != NULL);

	for (i = 0; i < state->dts_nspeculations; i++) {
		buf = spec[i].dtsp_buffer;
		if (buf == NULL)
			break;

		dtrace_buffer_free(buf);
		vfree(buf);
	}

	vfree(spec);
	state->dts_nspeculations = 0;
	state->dts_speculations = NULL;

out:
	preempt_enable();
	mutex_unlock(&dtrace_lock);
	mutex_unlock(&cpu_lock);

	return rval;
}

static void dtrace_end_probe(struct dtrace_state *state)
{
	dtrace_probe(dtrace_probeid_end, (uint64_t)(uintptr_t)state, 0, 0, 0,
		     0, 0, 0);

	state->dts_activity = DTRACE_ACTIVITY_STOPPED;

	dtrace_membar_enter();
}

int dtrace_state_stop(struct dtrace_state *state, processorid_t *cpu)
{
	processorid_t cpuid = state->dts_options[DTRACEOPT_CPU];

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE &&
	    state->dts_activity != DTRACE_ACTIVITY_DRAINING)
		return -EINVAL;

	/*
	 * We'll set the activity to DTRACE_ACTIVITY_DRAINING, and issue a sync
	 * to be sure that every CPU has seen it.  See below for the details
	 * on why this is done.
	 */
	preempt_disable();
	state->dts_activity = DTRACE_ACTIVITY_DRAINING;
	dtrace_sync();

	/*
	 * By this point, it is impossible for any CPU to be still processing
	 * with DTRACE_ACTIVITY_ACTIVE.  We can thus set our activity to
	 * DTRACE_ACTIVITY_COOLDOWN and know that we're not racing with any
	 * other CPU in dtrace_buffer_reserve().  This allows dtrace_probe()
	 * and callees to know that the activity is DTRACE_ACTIVITY_COOLDOWN
	 * iff we're in the END probe.
	 */
	state->dts_activity = DTRACE_ACTIVITY_COOLDOWN;
	dtrace_sync();
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_COOLDOWN);

	/*
	 * Finally, we can release the reserve and call the END probe.  We
	 * disable interrupts across calling the END probe to allow us to
	 * return the CPU on which we actually called the END probe.  This
	 * allows user-land to be sure that this CPU's principal buffer is
	 * processed last.
	 */
	state->dts_reserve = 0;

	/*
	 * Same as for BEGIN probe in dtrace_state_go().  The END probe must
	 * also fire on the enabled cpu.
	 */
	*cpu = (cpuid == DTRACE_CPUALL) ? smp_processor_id() : cpuid;
	dtrace_xcall(*cpu, (dtrace_xcall_t)dtrace_end_probe, state);

	dtrace_sync();
	preempt_enable();
	return 0;
}

int dtrace_state_option(struct dtrace_state *state, dtrace_optid_t option,
			dtrace_optval_t val)
{
	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE)
		return -EBUSY;

	if (option >= DTRACEOPT_MAX)
		return -EINVAL;

	if (option != DTRACEOPT_CPU && val < 0)
		return -EINVAL;

	switch (option) {
	case DTRACEOPT_DESTRUCTIVE:
		if (dtrace_destructive_disallow)
			return -EACCES;

		state->dts_cred.dcr_destructive = 1;
		break;

	case DTRACEOPT_BUFSIZE:
	case DTRACEOPT_DYNVARSIZE:
	case DTRACEOPT_AGGSIZE:
	case DTRACEOPT_SPECSIZE:
	case DTRACEOPT_STRSIZE:
		if (val < 0)
			return -EINVAL;

		/*
		 * If this is an otherwise negative value, set it to the
		 * highest multiple of 128m less than LONG_MAX.  Technically,
		 * we're adjusting the size without regard to the buffer
		 * resizing policy, but in fact, this has no effect -- if we
		 * set the buffer size to ~LONG_MAX and the buffer policy is
		 * ultimately set to be "manual", the buffer allocation is
		 * guaranteed to fail, if only because the allocation requires
		 * two buffers.  (We set the the size to the highest multiple
		 * of 128m because it ensures that the size will remain a
		 * multiple of a megabyte when repeatedly halved -- all the
		 * way down to 15m.)
		 */
		if (val >= LONG_MAX)
			val = LONG_MAX - (1 << 27) + 1;
	}

	state->dts_options[option] = val;

	return 0;
}

void dtrace_state_destroy(struct dtrace_state *state)
{
	struct dtrace_ecb	*ecb;
	struct dtrace_vstate	*vstate = &state->dts_vstate;
	int			i;
	struct dtrace_speculation *spec = state->dts_speculations;
	int			nspec = state->dts_nspeculations;
	uint32_t		match;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * First, retract any retained enablings for this state.
	 */
	dtrace_enabling_retract(state);
	ASSERT(state->dts_nretained == 0);

	if (state->dts_activity == DTRACE_ACTIVITY_ACTIVE ||
	    state->dts_activity == DTRACE_ACTIVITY_DRAINING) {
		/*
		 * We have managed to come into dtrace_state_destroy() on a
		 * hot enabling -- almost certainly because of a disorderly
		 * shutdown of a consumer.  (That is, a consumer that is
		 * exiting without having called dtrace_stop().) In this case,
		 * we're going to set our activity to be KILLED, and then
		 * issue a sync to be sure that everyone is out of probe
		 * context before we start blowing away ECBs.
		 */
		state->dts_activity = DTRACE_ACTIVITY_KILLED;
		dtrace_sync();
	}

	/*
	 * Release the credential hold we took in dtrace_state_create().
	 */
	if (state->dts_cred.dcr_cred != NULL)
		put_cred(state->dts_cred.dcr_cred);

	/*
	 * Now we can safely disable and destroy any enabled probes.  Because
	 * any DTRACE_PRIV_KERNEL probes may actually be slowing our progress
	 * (especially if they're all enabled), we take two passes through the
	 * ECBs: in the first, we disable just DTRACE_PRIV_KERNEL probes, and
	 * in the second we disable whatever is left over.
	 */
	for (match = DTRACE_PRIV_KERNEL; ; match = 0) {
		for (i = 0; i < state->dts_necbs; i++) {
			ecb = state->dts_ecbs[i];
			if (ecb == NULL)
				continue;

			if (match && ecb->dte_probe != NULL) {
				struct dtrace_probe	*probe =
							ecb->dte_probe;
				struct dtrace_provider	*prov =
							probe->dtpr_provider;

				if (!(prov->dtpv_priv.dtpp_flags & match))
					continue;
			}

			dtrace_ecb_disable(ecb);
			dtrace_ecb_destroy(ecb);
		}

		if (!match)
			break;
	}

	/*
	 * Before we free the buffers, perform one more sync to assure that
	 * every CPU is out of probe context.
	 */
	dtrace_sync();

	dtrace_buffer_free(state->dts_buffer);
	dtrace_buffer_free(state->dts_aggbuffer);

	for (i = 0; i < nspec; i++)
		dtrace_buffer_free(spec[i].dtsp_buffer);

	if (state->dts_cleaner != CYCLIC_NONE)
		cyclic_remove(state->dts_cleaner);

	if (state->dts_deadman != CYCLIC_NONE)
		cyclic_remove(state->dts_deadman);

	dtrace_dstate_fini(&vstate->dtvs_dynvars);
	dtrace_vstate_fini(vstate);
	vfree(state->dts_ecbs);

	/*
	 * If there were aggregations allocated, they should have been cleaned
	 * up by now, so we can get rid of the idr.
	 */
	idr_destroy(&state->dts_agg_idr);

	vfree(state->dts_buffer);
	vfree(state->dts_aggbuffer);

	for (i = 0; i < nspec; i++)
		vfree(spec[i].dtsp_buffer);

	vfree(spec);

	dtrace_format_destroy(state);

	kfree(state);
}
