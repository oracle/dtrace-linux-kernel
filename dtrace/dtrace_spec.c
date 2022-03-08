/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_spec.c
 * DESCRIPTION:	DTrace - speculation implementation
 *
 * Copyright (c) 2010, 2011, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/dtrace_cpu.h>
#include <linux/smp.h>
#include <asm/cmpxchg.h>

#include "dtrace.h"

/*
 * Given consumer state, this routine finds a speculation in the INACTIVE
 * state and transitions it into the ACTIVE state.  If there is no speculation
 * in the INACTIVE state, 0 is returned.  In this case, no error counter is
 * incremented -- it is up to the caller to take appropriate action.
 */
int dtrace_speculation(struct dtrace_state *state)
{
	int		i = 0;
	uint32_t	count, *stat = &state->dts_speculations_unavail;
	enum dtrace_speculation_state curr;

	while (i < state->dts_nspeculations) {
		struct dtrace_speculation *spec = &state->dts_speculations[i];

		curr = spec->dtsp_state;

		if (curr != DTRACESPEC_INACTIVE) {
			if (curr == DTRACESPEC_COMMITTINGMANY ||
			    curr == DTRACESPEC_COMMITTING ||
			    curr == DTRACESPEC_DISCARDING)
				stat = &state->dts_speculations_busy;

			i++;
			continue;
		}

		if (cmpxchg((uint32_t *)&spec->dtsp_state, curr,
			    DTRACESPEC_ACTIVE) == curr)
			return i + 1;
	}

	/*
	 * We couldn't find a speculation.  If we found as much as a single
	 * busy speculation buffer, we'll attribute this failure as "busy"
	 * instead of "unavail".
	 */
	do {
		count = *stat;
	} while (cmpxchg(stat, count, count + 1) != count);

	return 0;
}

/*
 * This routine commits an active speculation.  If the specified speculation
 * is not in a valid state to perform a commit(), this routine will silently do
 * nothing.  The state of the specified speculation is transitioned according
 * to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
void dtrace_speculation_commit(struct dtrace_state *state, processorid_t cpu,
			       dtrace_specid_t which)
{
	struct dtrace_speculation	*spec;
	struct dtrace_buffer		*src, *dest;
	uintptr_t			daddr, saddr, dlimit;
	enum dtrace_speculation_state	curr, new = 0;
	intptr_t			offs;

	if (which == 0)
		return;

	if (which > state->dts_nspeculations) {
		per_cpu_core(cpu)->cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	src = &spec->dtsp_buffer[cpu];
	dest = &state->dts_buffer[cpu];

	do {
		curr = spec->dtsp_state;

		if (curr == DTRACESPEC_COMMITTINGMANY)
			break;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_COMMITTING:
			/*
			 * This is only possible if we are (a) commit()'ing
			 * without having done a prior speculate() on this CPU
			 * and (b) racing with another commit() on a different
			 * CPU.  There's nothing to do -- we just assert that
			 * our offset is 0.
			 */
			ASSERT(src->dtb_offset == 0);
			return;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_COMMITTING;
			break;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is active on one CPU.  If our
			 * buffer offset is non-zero, we know that the one CPU
			 * must be us.  Otherwise, we are committing on a
			 * different CPU from the speculate(), and we must
			 * rely on being asynchronously cleaned.
			 */
			if (src->dtb_offset != 0) {
				new = DTRACESPEC_COMMITTING;
				break;
			}
			fallthrough;

		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_COMMITTINGMANY;
			break;

		default:
			ASSERT(0);
		}
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) !=
		 curr);

	/*
	 * We have set the state to indicate that we are committing this
	 * speculation.  Now reserve the necessary space in the destination
	 * buffer.
	 */
	offs = dtrace_buffer_reserve(dest, src->dtb_offset, sizeof(uint64_t),
				     state, NULL);
	if (offs < 0) {
		dtrace_buffer_drop(dest);
		goto out;
	}

	/*
	 * We have the space; copy the buffer across.  (Note that this is a
	 * highly subobtimal bcopy(); in the unlikely event that this becomes
	 * a serious performance issue, a high-performance DTrace-specific
	 * bcopy() should obviously be invented.)
	 */
	daddr = (uintptr_t)dest->dtb_tomax + offs;
	dlimit = daddr + src->dtb_offset;
	saddr = (uintptr_t)src->dtb_tomax;

	/*
	 * First, the aligned portion.
	 */
	while (dlimit - daddr >= sizeof(uint64_t)) {
		*((uint64_t *)daddr) = *((uint64_t *)saddr);
		*((uint64_t *)daddr) = *((uint64_t *)saddr);

		daddr += sizeof(uint64_t);
		saddr += sizeof(uint64_t);
	}

	/*
	 * Now any left-over bit...
	 */
	while (dlimit - daddr)
		*((uint8_t *)daddr++) = *((uint8_t *)saddr++);

	/*
	 * Finally, commit the reserved space in the destination buffer.
	 */
	dest->dtb_offset = offs + src->dtb_offset;

out:
	/*
	 * If we're lucky enough to be the only active CPU on this speculation
	 * buffer, we can just set the state back to DTRACESPEC_INACTIVE.
	 */
	if (curr == DTRACESPEC_ACTIVE ||
	    (curr == DTRACESPEC_ACTIVEONE && new == DTRACESPEC_COMMITTING)) {
		/*
		 * Will cause unused warning if DEBUG is not defined.
		 */
		uint32_t	rval =
				cmpxchg((uint32_t *)&spec->dtsp_state,
					DTRACESPEC_COMMITTING,
					DTRACESPEC_INACTIVE);

		ASSERT(rval == DTRACESPEC_COMMITTING);
		rval = 0; /* Avoid warning about unused variable if !DEBUG */
	}

	src->dtb_offset = 0;
	src->dtb_xamot_drops += src->dtb_drops;
	src->dtb_drops = 0;
}

/*
 * This routine discards an active speculation.  If the specified speculation
 * is not in a valid state to perform a discard(), this routine will silently
 * do nothing.  The state of the specified speculation is transitioned
 * according to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
void dtrace_speculation_discard(struct dtrace_state *state, processorid_t cpu,
				dtrace_specid_t which)
{
	struct dtrace_speculation	*spec;
	enum dtrace_speculation_state	curr, new = 0;
	struct dtrace_buffer		*buf;

	if (which == 0)
		return;

	if (which > state->dts_nspeculations) {
		per_cpu_core(cpu)->cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpu];

	do {
		curr = spec->dtsp_state;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_COMMITTING:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_ACTIVE:
		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_DISCARDING;
			break;

		case DTRACESPEC_ACTIVEONE:
			if (buf->dtb_offset != 0)
				new = DTRACESPEC_INACTIVE;
			else
				new = DTRACESPEC_DISCARDING;

			break;

		default:
			ASSERT(0);
		}
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) != curr);

	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously from cross call context to clean any speculations that are
 * in the COMMITTINGMANY or DISCARDING states.  These speculations may not be
 * transitioned back to the INACTIVE state until all CPUs have cleaned the
 * speculation.
 */
void dtrace_speculation_clean_here(struct dtrace_state *state)
{
	dtrace_icookie_t	cookie;
	processorid_t		cpu;
	struct dtrace_buffer	*dest;
	dtrace_specid_t		i;
	uint32_t		re_entry;

	DTRACE_SYNC_ENTER_CRITICAL(cookie, re_entry);
	cpu = smp_processor_id();
	dest = &state->dts_buffer[cpu];

	if (dest->dtb_tomax == NULL) {
		DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);
		return;
	}

	for (i = 0; i < state->dts_nspeculations; i++) {
		struct dtrace_speculation *spec = &state->dts_speculations[i];
		struct dtrace_buffer      *src = &spec->dtsp_buffer[cpu];

		if (src->dtb_tomax == NULL)
			continue;

		if (spec->dtsp_state == DTRACESPEC_DISCARDING) {
			src->dtb_offset = 0;
			continue;
		}

		if (spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		if (src->dtb_offset == 0)
			continue;

		dtrace_speculation_commit(state, cpu, i + 1);
	}

	DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry);
}

void dtrace_speculation_clean(struct dtrace_state *state)
{
	int		work = 0, rv;
	dtrace_specid_t	i;

	for (i = 0; i < state->dts_nspeculations; i++) {
		struct dtrace_speculation *spec = &state->dts_speculations[i];

		ASSERT(!spec->dtsp_cleaning);

		if (spec->dtsp_state != DTRACESPEC_DISCARDING &&
		    spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		work++;
		spec->dtsp_cleaning = 1;
	}

	if (!work)
		return;

	dtrace_xcall(DTRACE_CPUALL,
		     (dtrace_xcall_t)dtrace_speculation_clean_here, state);

	/*
	 * We now know that all CPUs have committed or discarded their
	 * speculation buffers, as appropriate.  We can now set the state
	 * to inactive.
	 */
	for (i = 0; i < state->dts_nspeculations; i++) {
		struct dtrace_speculation	*spec =
						&state->dts_speculations[i];
		enum dtrace_speculation_state	curr, new;

		if (!spec->dtsp_cleaning)
			continue;

		curr = spec->dtsp_state;
		ASSERT(curr == DTRACESPEC_DISCARDING ||
		       curr == DTRACESPEC_COMMITTINGMANY);

		new = DTRACESPEC_INACTIVE;

		rv = cmpxchg((uint32_t *)&spec->dtsp_state, curr, new);
		ASSERT(rv == curr);
		spec->dtsp_cleaning = 0;
	}
}

/*
 * Called as part of a speculate() to get the speculative buffer associated
 * with a given speculation.  Returns NULL if the specified speculation is not
 * in an ACTIVE state.  If the speculation is in the ACTIVEONE state -- and
 * the active CPU is not the specified CPU -- the speculation will be
 * atomically transitioned into the ACTIVEMANY state.
 */
struct dtrace_buffer *dtrace_speculation_buffer(struct dtrace_state *state,
                                                processorid_t cpu,
                                                dtrace_specid_t which)
{
	struct dtrace_speculation	*spec;
	enum dtrace_speculation_state	curr, new = 0;
	struct dtrace_buffer		*buf;

	if (which == 0)
		return NULL;

	if (which > state->dts_nspeculations) {
		per_cpu_core(cpu)->cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return NULL;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpu];

	do {
		curr = spec->dtsp_state;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_DISCARDING:
			return NULL;

		case DTRACESPEC_COMMITTING:
			ASSERT(buf->dtb_offset == 0);
			return NULL;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is currently active on one CPU.
			 * Check the offset in the buffer; if it's non-zero,
			 * that CPU must be us (and we leave the state alone).
			 * If it's zero, assume that we're starting on a new
			 * CPU -- and change the state to indicate that the
			 * speculation is active on more than one CPU.
			 */
			if (buf->dtb_offset != 0)
				return buf;

			new = DTRACESPEC_ACTIVEMANY;
			break;

		case DTRACESPEC_ACTIVEMANY:
			return buf;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_ACTIVEONE;
			break;

		default:
			ASSERT(0);
		}
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) != curr);

	ASSERT(new == DTRACESPEC_ACTIVEONE || new == DTRACESPEC_ACTIVEMANY);

	return buf;
}
