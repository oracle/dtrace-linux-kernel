/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_anon.c
 * DESCRIPTION:	DTrace - Anonymous state implementation
 *
 * Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.
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

#include "dtrace.h"

struct dtrace_anon	dtrace_anon;

struct dtrace_state *dtrace_anon_grab(void)
{
	struct dtrace_state	*state;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	state = dtrace_anon.dta_state;
	if (state == NULL) {
		ASSERT(dtrace_anon.dta_enabling == NULL);

		return NULL;
	}

	ASSERT(dtrace_anon.dta_enabling != NULL);
	ASSERT(dtrace_retained != NULL);

	dtrace_enabling_destroy(dtrace_anon.dta_enabling);
	dtrace_anon.dta_enabling = NULL;
	dtrace_anon.dta_state = NULL;

	return state;
}

void dtrace_anon_property(void)
{
	int			i, rv;
	struct dtrace_state	*state;
	struct dof_hdr		*dof;
	char			c[32];		/* enough for "dof-data-" + digits */

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; ; i++) {
		snprintf(c, sizeof(c), "dof-data-%d", i);

		dtrace_err_verbose = 1;

		dof = dtrace_dof_property(c);
		if (dof == NULL) {
			dtrace_err_verbose = 0;
			break;
		}

#ifdef FIXME
		/*
		 * We want to create anonymous state, so we need to transition
		 * the kernel debugger to indicate that DTrace is active.  If
		 * this fails (e.g. because the debugger has modified text in
		 * some way), we won't continue with the processing.
		 */
		if (kdi_dtrace_set(KDI_DTSET_DTRACE_ACTIVATE) != 0) {
			pr_info("kernel debugger active; "
				"anonymous enabling ignored.");
			dtrace_dof_destroy(dof);
			break;
		}
#endif

		/*
		 * If we haven't allocated an anonymous state, we'll do so now.
		 */
		state = dtrace_anon.dta_state;
		if (state == NULL) {
			state = dtrace_state_create(NULL);
			dtrace_anon.dta_state = state;

			if (state == NULL) {
				/*
				 * This basically shouldn't happen: there is no
				 * failure mode from dtrace_state_create().
				 * Still, the interface allows for a failure
				 * mode, and we want to fail as gracefully as
				 * possible: we'll emit an error message and
				 * cease processing anonymous state in this
				 * case.
				 */
				pr_warn("failed to create anonymous state");
				dtrace_dof_destroy(dof);
				break;
			}
		}

		rv = dtrace_dof_slurp(dof, &state->dts_vstate, current_cred(),
				      &dtrace_anon.dta_enabling, 0, TRUE);

		if (rv == 0)
			rv = dtrace_dof_options(dof, state);

		dtrace_err_verbose = 0;
		dtrace_dof_destroy(dof);

		if (rv != 0) {
			/*
			 * This is malformed DOF; chuck any anonymous state
			 * that we created.
			 */
			ASSERT(dtrace_anon.dta_enabling == NULL);
			dtrace_state_destroy(state);
			dtrace_anon.dta_state = NULL;
			break;
		}

		ASSERT(dtrace_anon.dta_enabling != NULL);
	}

	if (dtrace_anon.dta_enabling != NULL) {
		int	rval;

		/*
		 * dtrace_enabling_retain() can only fail because we are
		 * trying to retain more enablings than are allowed -- but
		 * we only have one anonymous enabling, and we are guaranteed
		 * to be allowed at least one retained enabling; we assert
		 * that dtrace_enabling_retain() returns success.
		 */
		rval = dtrace_enabling_retain(dtrace_anon.dta_enabling);
		ASSERT(rval == 0);

		dtrace_enabling_dump(dtrace_anon.dta_enabling);
	}
}
