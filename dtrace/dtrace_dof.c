/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_dof.c
 * DESCRIPTION:	DTrace - DOF implementation
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

#include <linux/dtrace_task_impl.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include "dtrace.h"

size_t			dtrace_difo_maxsize = 256 * 1024;
dtrace_optval_t		dtrace_dof_maxsize = 256 * 1024;
size_t			dtrace_actions_max = 16 * 1024;
dtrace_optval_t		dtrace_helper_actions_max = 32;
dtrace_optval_t		dtrace_helper_providers_max = 32;

static int		dtrace_helpers;

static uint32_t		dtrace_helptrace_next;
static uint32_t		dtrace_helptrace_nlocals;

#ifdef CONFIG_DT_DEBUG
int			dtrace_helptrace_enabled = 1;
#else
int			dtrace_helptrace_enabled = 0;
#endif
int			dtrace_helptrace_bufsize = 512 * 1024;
char			*dtrace_helptrace_buffer;

void dtrace_dof_error(struct dof_hdr *dof, const char *str)
{
	if (dtrace_err_verbose)
		pr_warn("failed to process DOF: %s", str);
	else
		dt_dbg_dof("Failed to process DOF: %s\n", str);

#ifdef DTRACE_ERRDEBUG
	dtrace_errdebug(str);
#endif
}

/*
 * Create DOF out of a currently enabled state.  Right now, we only create
 * DOF containing the run-time options -- but this could be expanded to create
 * complete DOF representing the enabled state.
 */
struct dof_hdr *dtrace_dof_create(struct dtrace_state *state)
{
	struct dof_hdr		*dof;
	struct dof_sec		*sec;
	struct dof_optdesc	*opt;

	int i, len = sizeof(struct dof_hdr) +
		roundup(sizeof(struct dof_sec),
			sizeof(uint64_t)) +
		sizeof(struct dof_optdesc) * DTRACEOPT_MAX;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	dof = vmalloc(len);
	if (dof == NULL)
		return NULL;

	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	dof->dofh_flags = 0;
	dof->dofh_hdrsize = sizeof(struct dof_hdr);
	dof->dofh_secsize = sizeof(struct dof_sec);
	dof->dofh_secnum = 1;   /* only DOF_SECT_OPTDESC */
	dof->dofh_secoff = sizeof(struct dof_hdr);
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;
	dof->dofh_pad = 0;

	/*
	 * Fill in the option section header...
	 */
	sec = (struct dof_sec *)((uintptr_t)dof + sizeof(struct dof_hdr));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof(uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof(struct dof_optdesc);

	opt = (struct dof_optdesc *)((uintptr_t)sec +
				     roundup(sizeof(struct dof_sec),
					     sizeof(uint64_t)));

	sec->dofs_offset = (uintptr_t)opt - (uintptr_t)dof;
	sec->dofs_size = sizeof(struct dof_optdesc) * DTRACEOPT_MAX;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		opt[i].dofo_option = i;
		opt[i].dofo_strtab = DOF_SECIDX_NONE;
		opt[i].dofo_value = state->dts_options[i];
	}

	return dof;
}

struct dof_hdr *dtrace_dof_copyin(void __user *argp, int *errp)
{
	struct dof_hdr	hdr, *dof;

	ASSERT(!MUTEX_HELD(&dtrace_lock));

	/*
	 * First, we're going to copyin() the sizeof(dof_hdr_t).
	 */
	if (copy_from_user(&hdr, argp, sizeof(hdr)) != 0) {
		dtrace_dof_error(NULL, "failed to copyin DOF header");
		*errp = -EFAULT;
		return NULL;
	}

	/*
	 * Now we'll allocate the entire DOF and copy it in -- provided
	 * that the length isn't outrageous.
	 */
	if (hdr.dofh_loadsz >= dtrace_dof_maxsize) {
		dtrace_dof_error(&hdr, "load size exceeds maximum");
		*errp = -E2BIG;
		return NULL;
	}

	if (hdr.dofh_loadsz < sizeof(hdr)) {
		dtrace_dof_error(&hdr, "invalid load size");
		*errp = -EINVAL;
		return NULL;
	}

	dof = vmalloc(hdr.dofh_loadsz);
	if (dof == NULL) {
		*errp = -ENOMEM;
		return NULL;
	}

	if (copy_from_user(dof, argp, hdr.dofh_loadsz) != 0 ||
		dof->dofh_loadsz != hdr.dofh_loadsz) {
		vfree(dof);
		*errp = -EFAULT;
		return NULL;
	}

	return dof;
}

struct dof_hdr *dtrace_dof_property(const char *name)
{
	uchar_t		*buf;
	uint64_t	loadsz;
	unsigned int	len, i;
	struct dof_hdr	*dof;

	/*
	 * Unfortunately, array of values in .conf files are always (and
	 * only) interpreted to be integer arrays.  We must read our DOF
	 * as an integer array, and then squeeze it into a byte array.
	 */
#ifdef FIXME
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dtrace_devi, 0,
				      (char *)name, (int **)&buf, &len) !=
	    DDI_PROP_SUCCESS)
		return NULL;
#else
	return NULL;
#endif

	for (i = 0; i < len; i++)
		buf[i] = (uchar_t)(((int *)buf)[i]);

	if (len < sizeof(struct dof_hdr)) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "truncated header");
		return NULL;
	}

	loadsz = ((struct dof_hdr *)buf)->dofh_loadsz;
	if (len < loadsz) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "truncated DOF");
		return NULL;
	}

	if (loadsz >= dtrace_dof_maxsize) {
#ifdef FIXME
		ddi_prop_free(buf);
#endif
		dtrace_dof_error(NULL, "oversized DOF");
		return NULL;
	}

	dof = vmalloc(loadsz);
	if (dof == NULL) {
		dtrace_dof_error(NULL, "out-of-memory");
		return NULL;
	}
	memcpy(dof, buf, loadsz);
#ifdef FIXME
	ddi_prop_free(buf);
#endif

	return dof;
}

void dtrace_dof_destroy(struct dof_hdr *dof)
{
	vfree(dof);
}

/*
 * Return the dof_sec_t pointer corresponding to a given section index.  If the
 * index is not valid, dtrace_dof_error() is called and NULL is returned.  If
 * a type other than DOF_SECT_NONE is specified, the header is checked against
 * this type and NULL is returned if the types do not match.
 */
static struct dof_sec *dtrace_dof_sect(struct dof_hdr *dof, uint32_t doftype,
                                       dof_secidx_t i)
{
	struct dof_sec *sec;

	sec = (struct dof_sec *)(uintptr_t) ((uintptr_t)dof +
					     dof->dofh_secoff +
					     i * dof->dofh_secsize);

	if (i >= dof->dofh_secnum) {
		dtrace_dof_error(dof, "referenced section index is invalid");
		return NULL;
	}

	if (!(sec->dofs_flags & DOF_SECF_LOAD)) {
		dtrace_dof_error(dof, "referenced section is not loadable");
		return NULL;
	}

	if (doftype != DOF_SECT_NONE && doftype != sec->dofs_type) {
		dtrace_dof_error(dof, "referenced section is the wrong type");
		return NULL;
	}

	return sec;
}

static struct dtrace_probedesc *dtrace_dof_probedesc(struct dof_hdr *dof,
                                                     struct dof_sec *sec,
                                                     struct dtrace_probedesc *desc)
{
	struct dof_probedesc	*probe;
	struct dof_sec		*strtab;
	uintptr_t		daddr = (uintptr_t)dof;
	uintptr_t		str;
	size_t			size;

	if (sec->dofs_type != DOF_SECT_PROBEDESC) {
		dtrace_dof_error(dof, "invalid probe section");
		return NULL;
	}

	if (sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in probe description");
		return NULL;
	}

	if (sec->dofs_offset + sizeof(struct dof_probedesc) >
	    dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated probe description");
		return NULL;
	}

	probe = (struct dof_probedesc *)(uintptr_t)(daddr + sec->dofs_offset);
	strtab = dtrace_dof_sect(dof, DOF_SECT_STRTAB, probe->dofp_strtab);

	if (strtab == NULL)
		return NULL;

	str = daddr + strtab->dofs_offset;
	size = strtab->dofs_size;

	if (probe->dofp_provider >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe provider");
		return NULL;
	}

	strncpy(desc->dtpd_provider, (char *)(str + probe->dofp_provider),
		min((size_t)DTRACE_PROVNAMELEN - 1,
		    size - probe->dofp_provider));

	if (probe->dofp_mod >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe module");
		return NULL;
	}

	strncpy(desc->dtpd_mod, (char *)(str + probe->dofp_mod),
		min((size_t)DTRACE_MODNAMELEN - 1, size - probe->dofp_mod));

	if (probe->dofp_func >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe function");
		return NULL;
	}

	strncpy(desc->dtpd_func, (char *)(str + probe->dofp_func),
		min((size_t)DTRACE_FUNCNAMELEN - 1, size - probe->dofp_func));

	if (probe->dofp_name >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe name");
		return NULL;
	}

	strncpy(desc->dtpd_name, (char *)(str + probe->dofp_name),
		min((size_t)DTRACE_NAMELEN - 1, size - probe->dofp_name));

	dt_dbg_dof("      ECB Probe %s:%s:%s:%s\n",
		   desc->dtpd_provider, desc->dtpd_mod, desc->dtpd_func,
		   desc->dtpd_name);

	return desc;
}

static struct dtrace_difo *dtrace_dof_difo(struct dof_hdr *dof,
                                           struct dof_sec *sec,
                                           struct dtrace_vstate *vstate,
                                           const struct cred *cr)
{
	struct dtrace_difo	*dp;
	size_t			ttl = 0;
	struct dof_difohdr	*dofd;
	uintptr_t		daddr = (uintptr_t)dof;
	size_t			max = dtrace_difo_maxsize;
	int			i, l, n;

	static const struct {
		int section;
		int bufoffs;
		int lenoffs;
		int entsize;
		int align;
		const char *msg;
	} difo[] = {
		{
			DOF_SECT_DIF,
			offsetof(struct dtrace_difo, dtdo_buf),
			offsetof(struct dtrace_difo, dtdo_len),
			sizeof(dif_instr_t),
			sizeof(dif_instr_t),
			"multiple DIF sections"
		},
		{
			DOF_SECT_INTTAB,
			offsetof(struct dtrace_difo, dtdo_inttab),
			offsetof(struct dtrace_difo, dtdo_intlen),
			sizeof(uint64_t),
			sizeof(uint64_t),
			"multiple integer tables"
		},
		{
			DOF_SECT_STRTAB,
			offsetof(struct dtrace_difo, dtdo_strtab),
			offsetof(struct dtrace_difo, dtdo_strlen),
			0,
			sizeof(char),
			"multiple string tables"
		},
		{
			DOF_SECT_VARTAB,
			offsetof(struct dtrace_difo, dtdo_vartab),
			offsetof(struct dtrace_difo, dtdo_varlen),
			sizeof(struct dtrace_difv),
			sizeof(uint_t),
			"multiple variable tables"
		},
		{
			DOF_SECT_NONE,
			0,
			0,
			0,
			0,
			NULL
		}
	};

	if (sec->dofs_type != DOF_SECT_DIFOHDR) {
		dtrace_dof_error(dof, "invalid DIFO header section");
		return NULL;
	}

	if (sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in DIFO header");
		return NULL;
	}

	if (sec->dofs_size < sizeof(struct dof_difohdr) ||
	    sec->dofs_size % sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "bad size in DIFO header");
		return NULL;
	}

	dofd = (struct dof_difohdr *)(uintptr_t)(daddr + sec->dofs_offset);
	n = (sec->dofs_size - sizeof(*dofd)) / sizeof(dof_secidx_t) + 1;

	dp = kzalloc(sizeof(struct dtrace_difo), GFP_KERNEL);
	if (dp == NULL) {
		dtrace_dof_error(dof, "out-of-memory");
		return NULL;
	}
	dp->dtdo_rtype = dofd->dofd_rtype;

	for (l = 0; l < n; l++) {
		struct dof_sec	*subsec;
		void		**bufp;
		uint32_t	*lenp;

		subsec = dtrace_dof_sect(dof, DOF_SECT_NONE,
					 dofd->dofd_links[l]);
		if (subsec == NULL)
			goto err; /* invalid section link */

		if (ttl + subsec->dofs_size > max) {
			dtrace_dof_error(dof, "exceeds maximum size");
			goto err;
		}

		ttl += subsec->dofs_size;

		for (i = 0; difo[i].section != DOF_SECT_NONE; i++) {
			if (subsec->dofs_type != difo[i].section)
				continue;

			if (!(subsec->dofs_flags & DOF_SECF_LOAD)) {
				dtrace_dof_error(dof, "section not loaded");
				goto err;
			}

			if (subsec->dofs_align != difo[i].align) {
				dtrace_dof_error(dof, "bad alignment");
				goto err;
			}

			bufp = (void **)((uintptr_t)dp + difo[i].bufoffs);
			lenp = (uint32_t *)((uintptr_t)dp + difo[i].lenoffs);

			if (*bufp != NULL) {
				dtrace_dof_error(dof, difo[i].msg);
				goto err;
			}

			if (difo[i].entsize != subsec->dofs_entsize) {
				dtrace_dof_error(dof, "entry size mismatch");
				goto err;
			}

			if (subsec->dofs_entsize != 0) {
				uint64_t	n = subsec->dofs_size;

				if (do_div(n, subsec->dofs_entsize) != 0) {
					dtrace_dof_error(dof,
							 "corrupt entry size");
					goto err;
				}
			}

			*lenp = subsec->dofs_size;
			*bufp = vmalloc(subsec->dofs_size);
			if (*bufp == NULL) {
				dtrace_dof_error(dof, "out-of-memory");
				goto err;
			}
			memcpy(*bufp,
			       (char *)(uintptr_t)(daddr + subsec->dofs_offset),
			       subsec->dofs_size);

			if (subsec->dofs_entsize != 0)
				*lenp /= subsec->dofs_entsize;

			break;
		}

		/*
		 * If we encounter a loadable DIFO sub-section that is not
		 * known to us, assume this is a broken program and fail.
		 */
		if (difo[i].section == DOF_SECT_NONE &&
		    (subsec->dofs_flags & DOF_SECF_LOAD)) {
			dtrace_dof_error(dof, "unrecognized DIFO subsection");
			goto err;
		}
	}

	if (dp->dtdo_buf == NULL) {
		/*
		 * We can't have a DIF object without DIF text.
		 */
		dtrace_dof_error(dof, "missing DIF text");
		goto err;
	}

	/*
	 * Before we validate the DIF object, run through the variable table
	 * looking for the strings -- if any of their size are under, we'll set
	 * their size to be the system-wide default string size.  Note that
	 * this should _not_ happen if the "strsize" option has been set --
	 * in this case, the compiler should have set the size to reflect the
	 * setting of the option.
	 */
	for (i = 0; i < dp->dtdo_varlen; i++) {
		struct dtrace_difv	*v = &dp->dtdo_vartab[i];
		struct dtrace_diftype	*t = &v->dtdv_type;

		if (v->dtdv_id < DIF_VAR_OTHER_UBASE)
			continue;

		if (t->dtdt_kind == DIF_TYPE_STRING && t->dtdt_size == 0)
			t->dtdt_size = dtrace_strsize_default;
	}

	if (dtrace_difo_validate(dp, vstate, DIF_DIR_NREGS, cr) != 0)
		goto err;

	dtrace_difo_init(dp, vstate);
	return dp;

err:
	if (dp->dtdo_buf != NULL)
		vfree(dp->dtdo_buf);
	if (dp->dtdo_inttab != NULL)
		vfree(dp->dtdo_inttab);
	if (dp->dtdo_strtab != NULL)
		vfree(dp->dtdo_strtab);
	if (dp->dtdo_vartab != NULL)
		vfree(dp->dtdo_vartab);

	kfree(dp);

	return NULL;
}

static struct dtrace_predicate *dtrace_dof_predicate(struct dof_hdr *dof,
                                                     struct dof_sec *sec,
                                                     struct dtrace_vstate *vstate,
                                                     const struct cred *cr)
{
	struct dtrace_difo *dp;

	if ((dp = dtrace_dof_difo(dof, sec, vstate, cr)) == NULL)
		return NULL;

	return dtrace_predicate_create(dp);
}

static struct dtrace_actdesc *dtrace_dof_actdesc(struct dof_hdr *dof,
                                                 struct dof_sec *sec,
                                                 struct dtrace_vstate *vstate,
                                                 const struct cred *cr)
{
	struct dtrace_actdesc	*act, *first = NULL, *last = NULL, *next;
	struct dof_actdesc	*desc;
	struct dof_sec		*difosec;
	size_t			offs;
	uintptr_t		daddr = (uintptr_t)dof;
	uint64_t		arg;
	dtrace_actkind_t	kind;

	if (sec->dofs_type != DOF_SECT_ACTDESC) {
		dtrace_dof_error(dof, "invalid action section");
		return NULL;
	}

	if (sec->dofs_offset + sizeof(struct dof_actdesc) > dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated action description");
		return NULL;
	}

	if (sec->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in action description");
		return NULL;
	}

	if (sec->dofs_size < sec->dofs_entsize) {
		dtrace_dof_error(dof, "section entry size exceeds total size");
		return NULL;
	}

	if (sec->dofs_entsize != sizeof(struct dof_actdesc)) {
		dtrace_dof_error(dof, "bad entry size in action description");
		return NULL;
	}

	/*
	 * Was: sec->dofs_size / sec->dofs_entsize > dtrace_actions_max
	 * but it is safer to simply avoid the division (it requires use of
	 * a macro in Linux to cover 64-bit division in a 32-bit kernel.
	 */
	if (sec->dofs_size > sec->dofs_entsize * dtrace_actions_max) {
		dtrace_dof_error(dof, "actions exceed dtrace_actions_max");
		return NULL;
	}

	for (offs = 0; offs < sec->dofs_size; offs += sec->dofs_entsize) {
		desc = (struct dof_actdesc *)(daddr +
					 (uintptr_t)sec->dofs_offset + offs);
		kind = (dtrace_actkind_t)desc->dofa_kind;

		if (DTRACEACT_ISPRINTFLIKE(kind) &&
		    (kind != DTRACEACT_PRINTA ||
		     desc->dofa_strtab != DOF_SECIDX_NONE)) {
			struct dof_sec	*strtab;
			char		*str, *fmt;
			uint64_t	i;

			/*
			 * The printf()-like actions must have a format string.
			 */
			strtab = dtrace_dof_sect(dof, DOF_SECT_STRTAB,
						 desc->dofa_strtab);
			if (strtab == NULL)
				goto err;

			str = (char *)((uintptr_t)dof +
				       (uintptr_t)strtab->dofs_offset);

			for (i = desc->dofa_arg; i < strtab->dofs_size; i++) {
				if (str[i] == '\0')
					break;
			}

			if (i >= strtab->dofs_size) {
				dtrace_dof_error(dof, "bogus format string");
				goto err;
			}

			if (i == desc->dofa_arg) {
				dtrace_dof_error(dof, "empty format string");
				goto err;
			}

			i -= desc->dofa_arg;
			fmt = vmalloc(i + 1);
			if (fmt == NULL) {
				dtrace_dof_error(dof, "out-of-memory");
				goto err;
			}
			memcpy(fmt, &str[desc->dofa_arg], i + 1);
			arg = (uint64_t)(uintptr_t)fmt;
		} else {
			if (kind == DTRACEACT_PRINTA) {
				ASSERT(desc->dofa_strtab == DOF_SECIDX_NONE);
				arg = 0;
			} else
				arg = desc->dofa_arg;
		}

		act = dtrace_actdesc_create(kind, desc->dofa_ntuple,
					    desc->dofa_uarg, arg);
		if (act == NULL)
			goto err;

		if (last != NULL)
			last->dtad_next = act;
		else
			first = act;

		last = act;

		if (desc->dofa_difo == DOF_SECIDX_NONE)
			continue;

		difosec = dtrace_dof_sect(dof, DOF_SECT_DIFOHDR,
					  desc->dofa_difo);
		if (difosec == NULL)
			goto err;

		act->dtad_difo = dtrace_dof_difo(dof, difosec, vstate, cr);

		if (act->dtad_difo == NULL)
			goto err;
	}

	ASSERT(first != NULL);
	return first;

err:
	for (act = first; act != NULL; act = next) {
		next = act->dtad_next;
		dtrace_actdesc_release(act, vstate);
	}

	return NULL;
}

static struct dtrace_ecbdesc *dtrace_dof_ecbdesc(struct dof_hdr *dof,
                                                 struct dof_sec *sec,
                                                 struct dtrace_vstate *vstate,
                                                 const struct cred *cr)
{
	struct dtrace_ecbdesc	*ep;
	struct dof_ecbdesc	*ecb;
	struct dtrace_probedesc	*desc;
	struct dtrace_predicate	*pred = NULL;

	if (sec->dofs_size < sizeof(struct dof_ecbdesc)) {
		dtrace_dof_error(dof, "truncated ECB description");
		return NULL;
	}

	if (sec->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in ECB description");
		return NULL;
	}

	ecb = (struct dof_ecbdesc *)
	  ((uintptr_t)dof + (uintptr_t)sec->dofs_offset);
	sec = dtrace_dof_sect(dof, DOF_SECT_PROBEDESC, ecb->dofe_probes);

	if (sec == NULL)
		return NULL;

	ep = kzalloc(sizeof(struct dtrace_ecbdesc), GFP_KERNEL);
	if (ep == NULL)
		return NULL;
	ep->dted_uarg = ecb->dofe_uarg;
	desc = &ep->dted_probe;

	if (dtrace_dof_probedesc(dof, sec, desc) == NULL)
		goto err;

	if (ecb->dofe_pred != DOF_SECIDX_NONE) {
		sec = dtrace_dof_sect(dof, DOF_SECT_DIFOHDR, ecb->dofe_pred);
		if (sec == NULL)
			goto err;

		pred = dtrace_dof_predicate(dof, sec, vstate, cr);
		if (pred == NULL)
			goto err;

		ep->dted_pred.dtpdd_predicate = pred;
	}

	if (ecb->dofe_actions != DOF_SECIDX_NONE) {
		sec = dtrace_dof_sect(dof, DOF_SECT_ACTDESC, ecb->dofe_actions);
		if (sec == NULL)
			goto err;

		ep->dted_action = dtrace_dof_actdesc(dof, sec, vstate, cr);

		if (ep->dted_action == NULL)
			goto err;
	}

	return ep;

err:
	if (pred != NULL)
		dtrace_predicate_release(pred, vstate);
	kfree(ep);
	return NULL;
}

/*
 * Apply the relocations from the specified 'sec' (a DOF_SECT_URELHDR) to the
 * specified DOF.  At present, this amounts to simply adding 'ubase' to the
 * site of any user SETX relocations to account for load object base address.
 * In the future, if we need other relocations, this function can be extended.
 */
static int dtrace_dof_relocate(struct dof_hdr *dof, struct dof_sec *sec,
			       uint64_t ubase)
{
	uintptr_t		daddr = (uintptr_t)dof;
	struct dof_relohdr	*dofr;
	struct dof_sec		*ss, *rs, *ts;
	struct dof_relodesc	*r;
	uint_t			i, n;

	dofr = (struct dof_relohdr *)(uintptr_t) (daddr + sec->dofs_offset);

	if (sec->dofs_size < sizeof(struct dof_relohdr) ||
	    sec->dofs_align != sizeof(dof_secidx_t)) {
		dtrace_dof_error(dof, "invalid relocation header");
		return -1;
	}

	ss = dtrace_dof_sect(dof, DOF_SECT_STRTAB, dofr->dofr_strtab);
	rs = dtrace_dof_sect(dof, DOF_SECT_RELTAB, dofr->dofr_relsec);
	ts = dtrace_dof_sect(dof, DOF_SECT_NONE, dofr->dofr_tgtsec);

	if (ss == NULL || rs == NULL || ts == NULL)
		return -1; /* dtrace_dof_error() has been called already */

	if (rs->dofs_entsize < sizeof(struct dof_relodesc) ||
	    rs->dofs_align != sizeof(uint64_t)) {
		dtrace_dof_error(dof, "invalid relocation section");
		return -1;
	}

	r = (struct dof_relodesc *)(uintptr_t)(daddr + rs->dofs_offset);
	/*
	 * Was: n = rs->dofs_size / rs->dofs_entsize;
	 * but on Linux we need to use a macro for the division to handle the
	 * possible case of 64-bit division on a 32-bit kernel.
	 */
	n = rs->dofs_size;
	do_div(n, rs->dofs_entsize);

	for (i = 0; i < n; i++) {
		uintptr_t taddr = daddr + ts->dofs_offset + r->dofr_offset;

		switch (r->dofr_type) {
		case DOF_RELO_NONE:
			break;
		case DOF_RELO_SETX:
			if (r->dofr_offset >= ts->dofs_size ||
			    r->dofr_offset + sizeof(uint64_t) >
				ts->dofs_size) {
				dtrace_dof_error(dof, "bad relocation offset");
				return -1;
			}

			if (!IS_ALIGNED(taddr, sizeof(uint64_t))) {
				dtrace_dof_error(dof, "misaligned setx relo");
				return -1;
			}

			/*
			 * This is a bit ugly but it is necessary for arm64,
			 * where the linking of shared libraries retains the
			 * relocation records for the .SUNW_dof section.  In
			 * that case, the runtime loader already performed the
			 * relocation, so we do not have to do anything here.
			 *
			 * We check for this situation by comparing the target
			 * address against the base address (ubase).  If it is
			 * larger, we assume the relocation already took place.
			 */
			if (*(uint64_t *)taddr > ubase)
				dt_dbg_dof("      Relocation by runtime " \
					   "loader: 0x%llx (base 0x%llx)\n",
					   *(uint64_t *)taddr, ubase);
			else {
				dt_dbg_dof("      Relocate 0x%llx + 0x%llx " \
					   "= 0x%llx\n",
					   *(uint64_t *)taddr, ubase,
					   *(uint64_t *)taddr + ubase);

				*(uint64_t *)taddr += ubase;
			}

			break;
		default:
			dtrace_dof_error(dof, "invalid relocation type");
			return -1;
		}

		r = (struct dof_relodesc *)((uintptr_t)r + rs->dofs_entsize);
	}

	return 0;
}

/*
 * The dof_hdr_t passed to dtrace_dof_slurp() should be a partially validated
 * header:  it should be at the front of a memory region that is at least
 * sizeof(dof_hdr_t) in size -- and then at least dof_hdr.dofh_loadsz in
 * size.  It need not be validated in any other way.
 */
int dtrace_dof_slurp(struct dof_hdr *dof, struct dtrace_vstate *vstate,
		     const struct cred *cr, struct dtrace_enabling **enabp,
		     uint64_t ubase, int noprobes)
{
	uint64_t		len = dof->dofh_loadsz, seclen;
	uintptr_t		daddr = (uintptr_t)dof;
	struct dtrace_ecbdesc	*ep;
	struct dtrace_enabling	*enab;
	uint_t			i;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dof->dofh_loadsz >= sizeof(struct dof_hdr));

	dt_dbg_dof("  DOF 0x%p Slurping...\n", dof);

	dt_dbg_dof("    DOF 0x%p Validating...\n", dof);

	/*
	 * Check the DOF header identification bytes.  In addition to checking
	 * valid settings, we also verify that unused bits/bytes are zeroed so
	 * we can use them later without fear of regressing existing binaries.
	 */
	if (memcmp(&dof->dofh_ident[DOF_ID_MAG0], DOF_MAG_STRING,
		   DOF_MAG_STRLEN) != 0) {
		dtrace_dof_error(dof, "DOF magic string mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_ILP32 &&
	    dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_LP64) {
		dtrace_dof_error(dof, "DOF has invalid data model");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_NATIVE) {
		dtrace_dof_error(dof, "DOF encoding mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_2) {
		dtrace_dof_error(dof, "DOF version mismatch");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFVERS] != DIF_VERSION_2) {
		dtrace_dof_error(dof, "DOF uses unsupported instruction set");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFIREG] > DIF_DIR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many integer registers");
		return -1;
	}

	if (dof->dofh_ident[DOF_ID_DIFTREG] > DIF_DTR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many tuple registers");
		return -1;
	}

	for (i = DOF_ID_PAD; i < DOF_ID_SIZE; i++) {
		if (dof->dofh_ident[i] != 0) {
			dtrace_dof_error(dof, "DOF has invalid ident byte set");
			return -1;
		}
	}

	if (dof->dofh_flags & ~DOF_FL_VALID) {
		dtrace_dof_error(dof, "DOF has invalid flag bits set");
		return -1;
	}

	if (dof->dofh_secsize == 0) {
		dtrace_dof_error(dof, "zero section header size");
		return -1;
	}

	/*
	 * Check that the section headers don't exceed the amount of DOF
	 * data.  Note that we cast the section size and number of sections
	 * to uint64_t's to prevent possible overflow in the multiplication.
	 */
	seclen = (uint64_t)dof->dofh_secnum * (uint64_t)dof->dofh_secsize;

	if (dof->dofh_secoff > len || seclen > len ||
	    dof->dofh_secoff + seclen > len) {
		dtrace_dof_error(dof, "truncated section headers");
		return -1;
	}

	if (!IS_ALIGNED(dof->dofh_secoff, sizeof(uint64_t))) {
		dtrace_dof_error(dof, "misaligned section headers");
		return -1;
	}

	if (!IS_ALIGNED(dof->dofh_secsize, sizeof(uint64_t))) {
		dtrace_dof_error(dof, "misaligned section size");
		return -1;
	}

	/*
	 * Take an initial pass through the section headers to be sure that
	 * the headers don't have stray offsets.  If the 'noprobes' flag is
	 * set, do not permit sections relating to providers, probes, or args.
	 */
	dt_dbg_dof("    DOF 0x%p Checking section offsets...\n", dof);

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)(daddr + (uintptr_t)dof->dofh_secoff +
					 i * dof->dofh_secsize);

		if (noprobes) {
			switch (sec->dofs_type) {
			case DOF_SECT_PROVIDER:
			case DOF_SECT_PROBES:
			case DOF_SECT_PRARGS:
			case DOF_SECT_PROFFS:
				dtrace_dof_error(
					dof, "illegal sections for enabling");
				return -1;
			}
		}

		if (DOF_SEC_ISLOADABLE(sec->dofs_type) &&
		    !(sec->dofs_flags & DOF_SECF_LOAD)) {
			dtrace_dof_error(
				dof, "loadable section with load flag unset");
			return -1;
		}

		/*
		 * Just ignore non-loadable sections.
		 */
		if (!(sec->dofs_flags & DOF_SECF_LOAD))
			continue;

		if (sec->dofs_align & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "bad section alignment");
			return -1;
		}

		if (sec->dofs_offset & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "misaligned section");
			return -1;
		}

		if (sec->dofs_offset > len || sec->dofs_size > len ||
		    sec->dofs_offset + sec->dofs_size > len) {
			dtrace_dof_error(dof, "corrupt section header");
			return -1;
		}

		if (sec->dofs_type == DOF_SECT_STRTAB && *((char *)daddr +
		    sec->dofs_offset + sec->dofs_size - 1) != '\0') {
			dtrace_dof_error(dof, "non-terminating string table");
			return -1;
		}
	}

	/*
	 * Take a second pass through the sections and locate and perform any
	 * relocations that are present.  We do this after the first pass to
	 * be sure that all sections have had their headers validated.
	 */
	dt_dbg_dof("    DOF 0x%p Performing relocations...\n", dof);

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)(daddr + (uintptr_t)dof->dofh_secoff +
					 i * dof->dofh_secsize);

		/*
		 * Skip sections that are not loadable.
		 */
		if (!(sec->dofs_flags & DOF_SECF_LOAD))
			continue;

		switch (sec->dofs_type) {
		case DOF_SECT_URELHDR:
			if (dtrace_dof_relocate(dof, sec, ubase) != 0)
				return -1;
			break;
		}
	}

	dt_dbg_dof("    DOF 0x%p Processing enablings...\n", dof);

	enab = *enabp;
	if (enab == NULL)
		enab = *enabp = dtrace_enabling_create(vstate);

	if (enab == NULL) {
		dt_dbg_dof("  DOF 0x%p Done slurping - no enablings\n", dof);
		return -1;
	}

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)(daddr + (uintptr_t)dof->dofh_secoff +
					 i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_ECBDESC)
			continue;

		ep = dtrace_dof_ecbdesc(dof, sec, vstate, cr);
		if (ep == NULL) {
			dt_dbg_dof("  DOF 0x%p Done slurping - ECB problem\n",
				   dof);
			dtrace_enabling_destroy(enab);
			*enabp = NULL;
			return -1;
		}

		dtrace_enabling_add(enab, ep);
	}

	dt_dbg_dof("    DOF 0x%p Enablings processed\n", dof);
	dt_dbg_dof("  DOF 0x%p Done slurping\n", dof);

	return 0;
}

/*
 * Process DOF for any options.  This should be called after the DOF has been
 * processed by dtrace_dof_slurp().
 */
int dtrace_dof_options(struct dof_hdr *dof, struct dtrace_state *state)
{
	int		i, rval;
	uint32_t	entsize;
	size_t 		offs;
	struct dof_optdesc *desc;

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)((uintptr_t)dof +
					 (uintptr_t)dof->dofh_secoff +
					 i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_OPTDESC)
			continue;

		if (sec->dofs_align != sizeof(uint64_t)) {
			dtrace_dof_error(
				dof, "bad alignment in option description");
			return -EINVAL;
		}

		entsize = sec->dofs_entsize;
		if (entsize == 0) {
			dtrace_dof_error(dof, "zeroed option entry size");
			return -EINVAL;
		}

		if (entsize < sizeof(struct dof_optdesc)) {
			dtrace_dof_error(dof, "bad option entry size");
			return -EINVAL;
		}

		for (offs = 0; offs < sec->dofs_size; offs += entsize) {
			desc = (struct dof_optdesc *)((uintptr_t)dof +
						 (uintptr_t)sec->dofs_offset +
						 offs);

			if (desc->dofo_strtab != DOF_SECIDX_NONE) {
				dtrace_dof_error(
					dof, "non-zero option string");
				return -EINVAL;
			}

			if (desc->dofo_value == DTRACEOPT_UNSET) {
				dtrace_dof_error(dof, "unset option");
				return -EINVAL;
			}

			rval = dtrace_state_option(state, desc->dofo_option,
						   desc->dofo_value);
			if (rval != 0) {
				dtrace_dof_error(dof, "rejected option");
				return rval;
			}
		}
	}

	return 0;
}

static struct dtrace_helpers *dtrace_helpers_create(struct task_struct *curr)
{
	struct dtrace_helpers	*dth;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (curr->dt_task == NULL)
		return NULL;

	ASSERT(curr->dt_task->dt_helpers == NULL);

	dth = kzalloc(sizeof(struct dtrace_helpers), GFP_KERNEL);
	if (dth == NULL)
		return NULL;

	dth->dthps_actions = vzalloc(sizeof(struct dtrace_helper_action *) *
				     DTRACE_NHELPER_ACTIONS);
	if (dth->dthps_actions == NULL) {
		kfree(dth);
		return NULL;
	}

	curr->dt_task->dt_helpers = dth;
	dtrace_helpers++;

	dt_dbg_dof("  Helpers allocated for task 0x%p (%d system-wide)\n",
		   curr, dtrace_helpers);

	return dth;
}

static int dtrace_helper_validate(struct dtrace_helper_action *helper)
{
	int			err = 0, i;
	struct dtrace_difo	*dp;

	dp = helper->dtha_predicate;
	if (dp != NULL)
		err += dtrace_difo_validate_helper(dp);

	for (i = 0; i < helper->dtha_nactions; i++)
		err += dtrace_difo_validate_helper(helper->dtha_actions[i]);

	return (err == 0);
}

static int dtrace_helper_provider_validate(struct dof_hdr *dof,
					   struct dof_sec *sec)
{
	uintptr_t		daddr = (uintptr_t)dof;
	struct dof_sec		*str_sec, *prb_sec, *arg_sec, *off_sec,
				*enoff_sec;
	struct dof_provider	*prov;
	struct dof_probe	*prb;
	uint8_t			*arg;
	char			*strtab, *typestr;
	dof_stridx_t		typeidx;
	size_t			typesz;
	uint_t			nprobes, j, k;

	ASSERT(sec->dofs_type == DOF_SECT_PROVIDER);

	if (sec->dofs_offset & (sizeof(uint_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return -1;
	}

	/*
	 * The section needs to be large enough to contain the DOF provider
	 * structure appropriate for the given version.
	 */
	if (sec->dofs_size <
	    ((dof->dofh_ident[DOF_ID_VERSION] == DOF_VERSION_1)
			? offsetof(struct dof_provider, dofpv_prenoffs)
			: sizeof(struct dof_provider))) {
		dtrace_dof_error(dof, "provider section too small");
		return -1;
	}

	prov = (struct dof_provider *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = dtrace_dof_sect(dof, DOF_SECT_STRTAB, prov->dofpv_strtab);
	prb_sec = dtrace_dof_sect(dof, DOF_SECT_PROBES, prov->dofpv_probes);
	arg_sec = dtrace_dof_sect(dof, DOF_SECT_PRARGS, prov->dofpv_prargs);
	off_sec = dtrace_dof_sect(dof, DOF_SECT_PROFFS, prov->dofpv_proffs);

	if (str_sec == NULL || prb_sec == NULL ||
	    arg_sec == NULL || off_sec == NULL)
		return -1;

	enoff_sec = NULL;

	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    prov->dofpv_prenoffs != DOF_SECT_NONE) {
		enoff_sec = dtrace_dof_sect(dof, DOF_SECT_PRENOFFS,
					    prov->dofpv_prenoffs);

		if (enoff_sec == NULL)
			return -1;
	}

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	if (prov->dofpv_name >= str_sec->dofs_size ||
	    strlen(strtab + prov->dofpv_name) >= DTRACE_PROVNAMELEN) {
		dtrace_dof_error(dof, "invalid provider name");
		return -1;
	}

	if (prb_sec->dofs_entsize == 0 ||
	    prb_sec->dofs_entsize > prb_sec->dofs_size) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	if (prb_sec->dofs_entsize & (sizeof(uintptr_t) - 1)) {
		dtrace_dof_error(dof, "misaligned entry size");
		return -1;
	}

	if (off_sec->dofs_entsize != sizeof(uint32_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	if (off_sec->dofs_offset & (sizeof(uint32_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return -1;
	}

	if (arg_sec->dofs_entsize != sizeof(uint8_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return -1;
	}

	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);
	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	dt_dbg_dof("    DOF 0x%p %s::: with %d probes\n",
		   dof, strtab + prov->dofpv_name, nprobes);

	/*
	 * Take a pass through the probes to check for errors.
	 */
	for (j = 0; j < nprobes; j++) {
		prb = (struct dof_probe *)(uintptr_t)
			(daddr + prb_sec->dofs_offset +
			 j * prb_sec->dofs_entsize);

		if (prb->dofpr_func >= str_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid function name");
			return -1;
		}

		if (strlen(strtab + prb->dofpr_func) >= DTRACE_FUNCNAMELEN) {
			dtrace_dof_error(dof, "function name too long");
			return -1;
		}

		if (prb->dofpr_name >= str_sec->dofs_size ||
		    strlen(strtab + prb->dofpr_name) >= DTRACE_NAMELEN) {
			dtrace_dof_error(dof, "invalid probe name");
			return -1;
		}

		/*
		 * The offset count must not wrap the index, and the offsets
		 * must also not overflow the section's data.
		 */
		if (prb->dofpr_offidx + prb->dofpr_noffs < prb->dofpr_offidx ||
		    (prb->dofpr_offidx + prb->dofpr_noffs) *
		    off_sec->dofs_entsize > off_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid probe offset");
			return -1;
		}

		if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1) {
			/*
			 * If there's no is-enabled offset section, make sure
			 * there aren't any is-enabled offsets. Otherwise
			 * perform the same checks as for probe offsets
			 * (immediately above).
			 */
			if (enoff_sec == NULL) {
				if (prb->dofpr_enoffidx != 0 ||
				    prb->dofpr_nenoffs != 0) {
					dtrace_dof_error(dof,
							 "is-enabled offsets "
							 "with null section");
					return -1;
				}
			} else if (prb->dofpr_enoffidx + prb->dofpr_nenoffs <
				   prb->dofpr_enoffidx ||
				   (prb->dofpr_enoffidx + prb->dofpr_nenoffs) *
				   enoff_sec->dofs_entsize >
				   enoff_sec->dofs_size) {
				dtrace_dof_error(dof, "invalid is-enabled "
						      "offset");
				return -1;
			}

			if (prb->dofpr_noffs + prb->dofpr_nenoffs == 0) {
				dtrace_dof_error(dof, "zero probe and "
						      "is-enabled offsets");
				return -1;
			}
		} else if (prb->dofpr_noffs == 0) {
			dtrace_dof_error(dof, "zero probe offsets");
			return -1;
		}

		if (prb->dofpr_argidx + prb->dofpr_xargc < prb->dofpr_argidx ||
		    (prb->dofpr_argidx + prb->dofpr_xargc) *
		    arg_sec->dofs_entsize > arg_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid args");
			return -1;
		}

		typeidx = prb->dofpr_nargv;
		typestr = strtab + prb->dofpr_nargv;
		for (k = 0; k < prb->dofpr_nargc; k++) {
			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad native argument "
						      "type");
				return -1;
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "native argument type "
						      "too long");
				return -1;
			}

			typeidx += typesz;
			typestr += typesz;
		}

		typeidx = prb->dofpr_xargv;
		typestr = strtab + prb->dofpr_xargv;
		for (k = 0; k < prb->dofpr_xargc; k++) {
			if (arg[prb->dofpr_argidx + k] > prb->dofpr_nargc) {
				dtrace_dof_error(dof, "bad native argument "
						      "index");
				return -1;
			}

			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad translated "
						      "argument type");
				return -1;
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "translated argument "
						      "type too long");
				return -1;
			}

			typeidx += typesz;
			typestr += typesz;
		}

		dt_dbg_dof("      Probe %d %s:%s:%s:%s with %d offsets, "
			   "%d is-enabled offsets\n", j,
			   strtab + prov->dofpv_name, "",
			   strtab + prb->dofpr_func, strtab + prb->dofpr_name,
			   prb->dofpr_noffs, prb->dofpr_nenoffs);
	}

	return 0;
}

static void dtrace_helper_action_destroy(struct dtrace_helper_action *helper,
					 struct dtrace_vstate *vstate)
{
	int	i;

	if (helper->dtha_predicate != NULL)
		dtrace_difo_release(helper->dtha_predicate, vstate);

	for (i = 0; i < helper->dtha_nactions; i++) {
		ASSERT(helper->dtha_actions[i] != NULL);
		dtrace_difo_release(helper->dtha_actions[i], vstate);
	}

	vfree(helper->dtha_actions);
	kfree(helper);
}

static int dtrace_helper_action_add(int which, struct dtrace_ecbdesc *ep)
{
	struct dtrace_helpers		*dth;
	struct dtrace_helper_action	*helper, *last;
	struct dtrace_actdesc		*act;
	struct dtrace_vstate		*vstate;
	struct dtrace_predicate		*pred;
	int				count = 0, nactions = 0, i;

	if (which < 0 || which >= DTRACE_NHELPER_ACTIONS)
		return -EINVAL;

	if (current->dt_task == NULL)
		return -ENOMEM;

	dth = current->dt_task->dt_helpers;
	last = dth->dthps_actions[which];
	vstate = &dth->dthps_vstate;

	for (count = 0; last != NULL; last = last->dtha_next) {
		count++;
		if (last->dtha_next == NULL)
			break;
	}

	/*
	 * If we already have dtrace_helper_actions_max helper actions for this
	 * helper action type, we'll refuse to add a new one.
	 */
	if (count >= dtrace_helper_actions_max)
		return -ENOSPC;

	helper = kzalloc(sizeof(struct dtrace_helper_action), GFP_KERNEL);
	if (helper == NULL)
		return -ENOMEM;

	helper->dtha_generation = dth->dthps_generation;

	pred = ep->dted_pred.dtpdd_predicate;
	if (pred != NULL) {
		ASSERT(pred->dtp_difo != NULL);
		dtrace_difo_hold(pred->dtp_difo);
		helper->dtha_predicate = pred->dtp_difo;
	}

	for (act = ep->dted_action; act != NULL; act = act->dtad_next) {
		if (act->dtad_kind != DTRACEACT_DIFEXPR)
			goto err;

		if (act->dtad_difo == NULL)
			goto err;

		nactions++;
	}

	helper->dtha_actions = vzalloc(sizeof(struct dtrace_difo *) *
				       (helper->dtha_nactions = nactions));
	if (helper->dtha_actions == NULL)
		goto err;

	for (act = ep->dted_action, i = 0; act != NULL; act = act->dtad_next) {
		dtrace_difo_hold(act->dtad_difo);
		helper->dtha_actions[i++] = act->dtad_difo;
	}

	if (!dtrace_helper_validate(helper))
		goto err;

	if (last == NULL)
		dth->dthps_actions[which] = helper;
	else
		last->dtha_next = helper;

	if (vstate->dtvs_nlocals > dtrace_helptrace_nlocals) {
		dtrace_helptrace_nlocals = vstate->dtvs_nlocals;
		dtrace_helptrace_next = 0;
	}

	return 0;

err:
	dtrace_helper_action_destroy(helper, vstate);
	if (helper->dtha_actions != NULL)
		vfree(helper->dtha_actions);
	else
		return -ENOMEM;

	return -EINVAL;
}

static int dtrace_helper_provider_add(struct dof_helper *dofhp, int gen)
{
	struct dtrace_helpers		*dth;
	struct dtrace_helper_provider	*hprov, **tmp_provs;
	uint_t				tmp_maxprovs, i;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (current->dt_task == NULL)
		return -ENOMEM;

	dth = current->dt_task->dt_helpers;
	ASSERT(dth != NULL);

	/*
	 * If we already have dtrace_helper_providers_max helper providers,
	 * we're refuse to add a new one.
	 */
	if (dth->dthps_nprovs >= dtrace_helper_providers_max)
		return -ENOSPC;

	/*
	 * Check to make sure this isn't a duplicate.
	 */
	for (i = 0; i < dth->dthps_nprovs; i++) {
		if (dofhp->dofhp_addr ==
		    dth->dthps_provs[i]->dthp_prov.dofhp_addr)
			return -EALREADY;
	}

	hprov = kzalloc(sizeof(struct dtrace_helper_provider), GFP_KERNEL);
	if (hprov == NULL)
		return -ENOMEM;
	hprov->dthp_prov = *dofhp;
	hprov->dthp_ref = 1;
	hprov->dthp_generation = gen;

	/*
	 * Allocate a bigger table for helper providers if it's already full.
	 */
	if (dth->dthps_maxprovs == dth->dthps_nprovs) {
		tmp_maxprovs = dth->dthps_maxprovs;
		tmp_provs = dth->dthps_provs;

		if (dth->dthps_maxprovs == 0)
			dth->dthps_maxprovs = 2;
		else
			dth->dthps_maxprovs *= 2;

		if (dth->dthps_maxprovs > dtrace_helper_providers_max)
			dth->dthps_maxprovs = dtrace_helper_providers_max;

		ASSERT(tmp_maxprovs < dth->dthps_maxprovs);

		dth->dthps_provs =
		  vzalloc(dth->dthps_maxprovs *
			  sizeof(struct dtrace_helper_provider *));

		if (dth->dthps_provs == NULL) {
			kfree(hprov);
			return -ENOMEM;
		}

		if (tmp_provs != NULL) {
			memcpy(dth->dthps_provs, tmp_provs,
			       tmp_maxprovs *
			       sizeof(struct dtrace_helper_provider *));
			vfree(tmp_provs);
		}
	}

	dth->dthps_provs[dth->dthps_nprovs] = hprov;
	dth->dthps_nprovs++;

	return 0;
}

static void dtrace_helper_provider_destroy(struct dtrace_helper_provider *hprov)
{
	mutex_lock(&dtrace_lock);

	if (--hprov->dthp_ref == 0) {
		struct dof_hdr	*dof;

		mutex_unlock(&dtrace_lock);

		dof = (struct dof_hdr *)(uintptr_t)hprov->dthp_prov.dofhp_dof;
		dtrace_dof_destroy(dof);
		kfree(hprov);
	} else
		mutex_unlock(&dtrace_lock);
}

static void dtrace_dofattr2attr(struct dtrace_attribute *attr,
				const dof_attr_t dofattr)
{
	attr->dtat_name = DOF_ATTR_NAME(dofattr);
	attr->dtat_data = DOF_ATTR_DATA(dofattr);
	attr->dtat_class = DOF_ATTR_CLASS(dofattr);
}

static void dtrace_dofprov2hprov(struct dtrace_helper_provdesc *hprov,
				 const struct dof_provider *dofprov,
				 char *strtab)
{
	hprov->dthpv_provname = strtab + dofprov->dofpv_name;
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_provider,
			    dofprov->dofpv_provattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_mod,
			    dofprov->dofpv_modattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_func,
			    dofprov->dofpv_funcattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_name,
			    dofprov->dofpv_nameattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_args,
			    dofprov->dofpv_argsattr);
}

static void dtrace_helper_provider_remove_one(struct dof_helper *dhp,
					      struct dof_sec *sec, pid_t pid)
{
	uintptr_t			daddr = (uintptr_t)dhp->dofhp_dof;
	struct dof_hdr			*dof = (struct dof_hdr *)daddr;
	struct dof_sec			*str_sec;
	struct dof_provider		*prov;
	char				*strtab;
	struct dtrace_helper_provdesc	dhpv;
	struct dtrace_meta		*meta = dtrace_meta_pid;
	struct dtrace_mops		*mops = &meta->dtm_mops;

	prov = (struct dof_provider *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (struct dof_sec *)(uintptr_t)(daddr + dof->dofh_secoff +
						prov->dofpv_strtab *
						dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, prov, strtab);

	dt_dbg_dof("    Removing provider %s for PID %d\n",
		   dhpv.dthpv_provname, pid);

	mops->dtms_remove_pid(meta->dtm_arg, &dhpv, pid);

	meta->dtm_count--;
}

static void dtrace_helper_provider_remove(struct dof_helper *dhp, pid_t pid)
{
	uintptr_t	daddr = (uintptr_t)dhp->dofhp_dof;
	struct dof_hdr	*dof = (struct dof_hdr *)daddr;
	int		i;

	ASSERT(MUTEX_HELD(&dtrace_meta_lock));

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)(uintptr_t) (daddr + dof->dofh_secoff +
						     i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provider_remove_one(dhp, sec, pid);
	}
}

static void dtrace_helper_provide_one(struct dof_helper *dhp,
				      struct dof_sec *sec,
				      pid_t pid)
{
	uintptr_t	daddr = (uintptr_t)dhp->dofhp_dof;
	uint32_t	*off, *enoff;
	uint8_t		*arg;
	char		*strtab;
	uint_t		i, nprobes;
	void		*parg;

	struct dof_hdr			*dof = (struct dof_hdr *)daddr;
	struct dof_sec			*str_sec, *prb_sec, *arg_sec, *off_sec,
					*enoff_sec;
	struct dof_provider		*prov;
	struct dof_probe		*probe;
	struct dtrace_helper_provdesc	dhpv;
	struct dtrace_helper_probedesc	dhpb;
	struct dtrace_meta		*meta = dtrace_meta_pid;
	struct dtrace_mops		*mops = &meta->dtm_mops;

	prov = (struct dof_provider *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (struct dof_sec *)(uintptr_t)(daddr + dof->dofh_secoff +
						prov->dofpv_strtab *
						dof->dofh_secsize);
	prb_sec = (struct dof_sec *)(uintptr_t)(daddr + dof->dofh_secoff +
						prov->dofpv_probes *
						dof->dofh_secsize);
	arg_sec = (struct dof_sec *)(uintptr_t)(daddr + dof->dofh_secoff +
						prov->dofpv_prargs *
						dof->dofh_secsize);
	off_sec = (struct dof_sec *)(uintptr_t)(daddr + dof->dofh_secoff +
						prov->dofpv_proffs *
						dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);
	off = (uint32_t *)(uintptr_t)(daddr + off_sec->dofs_offset);
	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);
	enoff = NULL;

	/*
	 * See dtrace_helper_provider_validate().
	 */
	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    prov->dofpv_prenoffs != DOF_SECT_NONE) {
		enoff_sec = (struct dof_sec *)(uintptr_t)
		  (daddr + dof->dofh_secoff +
		   prov->dofpv_prenoffs * dof->dofh_secsize);
		enoff = (uint32_t *)(uintptr_t)
		  (daddr + enoff_sec->dofs_offset);
	}

	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, prov, strtab);

	dt_dbg_dof("    Creating provider %s for PID %d\n",
		   strtab + prov->dofpv_name, pid);

	/*
	 * This used to just 'return;' when parg is NULL, but that causes the
	 * cleanup code (dtrace_helper_provider_remove[_one]) to make a call
	 * to dtms_remove_pid() for a provider that never got created.
	 *
	 * If we fail to provide this provider, mark it as something to ignore,
	 * so we don't try to process it during cleanup.
	 */
	parg = mops->dtms_provide_pid(meta->dtm_arg, &dhpv, pid);
	if (parg == NULL) {
		sec->dofs_type = DOF_SECT_NONE;
		return;
	}

	meta->dtm_count++;

	/*
	 * Create the probes.
	 */
	for (i = 0; i < nprobes; i++) {
		probe = (struct dof_probe *)(uintptr_t)(daddr +
						   prb_sec->dofs_offset +
						   i * prb_sec->dofs_entsize);

		dhpb.dthpb_mod = dhp->dofhp_mod;
		dhpb.dthpb_func = strtab + probe->dofpr_func;
		dhpb.dthpb_name = strtab + probe->dofpr_name;
		dhpb.dthpb_base = probe->dofpr_addr;
		dhpb.dthpb_offs = off + probe->dofpr_offidx;
		dhpb.dthpb_noffs = probe->dofpr_noffs;

		if (enoff != NULL) {
			dhpb.dthpb_enoffs = enoff + probe->dofpr_enoffidx;
			dhpb.dthpb_nenoffs = probe->dofpr_nenoffs;
		} else {
			dhpb.dthpb_enoffs = NULL;
			dhpb.dthpb_nenoffs = 0;
		}

		dhpb.dthpb_args = arg + probe->dofpr_argidx;
		dhpb.dthpb_nargc = probe->dofpr_nargc;
		dhpb.dthpb_xargc = probe->dofpr_xargc;
		dhpb.dthpb_ntypes = strtab + probe->dofpr_nargv;
		dhpb.dthpb_xtypes = strtab + probe->dofpr_xargv;

		dt_dbg_dof("      Creating probe %s:%s:%s:%s\n",
			   strtab + prov->dofpv_name, "", dhpb.dthpb_func,
			   dhpb.dthpb_name);

		mops->dtms_create_probe(meta->dtm_arg, parg, &dhpb);
	}
}

void dtrace_helper_provide(struct dof_helper *dhp, pid_t pid)
{
	uintptr_t	daddr = (uintptr_t)dhp->dofhp_dof;
	struct dof_hdr	*dof = (struct dof_hdr *)daddr;
	int		i;

	ASSERT(MUTEX_HELD(&dtrace_meta_lock));

	for (i = 0; i < dof->dofh_secnum; i++) {
		struct dof_sec *sec;

		sec = (struct dof_sec *)(uintptr_t) (daddr + dof->dofh_secoff +
						     i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provide_one(dhp, sec, pid);
	}

	/*
	 * We may have just created probes, so we must now rematch against any
	 * retained enablings.  Note that this call will acquire both cpu_lock
	 * and dtrace_lock; the fact that we are holding dtrace_meta_lock now
	 * is what defines the ordering with respect to these three locks.
	 */
	dt_dbg_dof("    Re-matching against any retained enablings\n");
	dtrace_enabling_matchall();
}

static void dtrace_helper_provider_register(struct task_struct *tsk,
					    struct dtrace_helpers *dth,
					    struct dof_helper *dofhp)
{
	ASSERT(!MUTEX_HELD(&dtrace_lock));

	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (!dtrace_attached() || dtrace_meta_pid == NULL) {
		dt_dbg_dof("    No meta provider registered -- deferred\n");

		/*
		 * If the dtrace module is loaded but not attached, or if there
		 * isn't a meta provider registered to deal with these provider
		 * descriptions, we need to postpone creating the actual
		 * providers until later.
		 */
		if (dth->dthps_next == NULL && dth->dthps_prev == NULL &&
		    dtrace_deferred_pid != dth) {
			dth->dthps_deferred = 1;
			dth->dthps_pid = tsk->pid;
			dth->dthps_next = dtrace_deferred_pid;
			dth->dthps_prev = NULL;
			if (dtrace_deferred_pid != NULL)
				dtrace_deferred_pid->dthps_prev = dth;
			dtrace_deferred_pid = dth;
		}

		mutex_unlock(&dtrace_lock);
	} else if (dofhp != NULL) {
		/*
		 * If the dtrace module is loaded and we have a particular
		 * helper provider description, pass that off to the meta
		 * provider.
		 */
		mutex_unlock(&dtrace_lock);

		dtrace_helper_provide(dofhp, tsk->pid);
	} else {
		/*
		 * Otherwise, just pass all the helper provider descriptions
		 * off to the meta provider.
		 */
		int	i;

		mutex_unlock(&dtrace_lock);

		for (i = 0; i < dth->dthps_nprovs; i++) {
			dtrace_helper_provide(&dth->dthps_provs[i]->dthp_prov,
					      tsk->pid);
		}
	}

	mutex_unlock(&dtrace_meta_lock);
}

int dtrace_helper_slurp(struct dof_hdr *dof, struct dof_helper *dhp)
{
	struct dtrace_helpers	*dth;
	struct dtrace_vstate	*vstate;
	struct dtrace_enabling	*enab = NULL;
	int			i, gen, rv;
	int			nhelpers = 0, nprovs = 0, destroy = 1;
	uintptr_t		daddr = (uintptr_t)dof;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (current->dt_task == NULL)
		return -1;

	dth = current->dt_task->dt_helpers;
	if (dth == NULL)
		dth = dtrace_helpers_create(current);

	if (dth == NULL) {
		dtrace_dof_destroy(dof);
		return -1;
	}

	dt_dbg_dof("DOF 0x%p from helper {'%s', %p, %p}...\n",
		   dof, dhp ? dhp->dofhp_mod : "<none>",
			dhp ? (void *)(dhp->dofhp_addr) : NULL,
			dhp ? (void *)(dhp->dofhp_dof) : NULL);

	vstate = &dth->dthps_vstate;

	rv = dtrace_dof_slurp(dof, vstate, NULL, &enab,
			      dhp != NULL ? dhp->dofhp_addr : 0, FALSE);
	if (rv != 0) {
		dtrace_dof_destroy(dof);
		return rv;
	}

	/*
	 * Look for helper providers and validate their descriptions.
	 */
	if (dhp != NULL) {
		dt_dbg_dof("  DOF 0x%p Validating providers...\n", dof);

		for (i = 0; i < dof->dofh_secnum; i++) {
			struct dof_sec *sec;

			sec = (struct dof_sec *)(uintptr_t)
				(daddr + dof->dofh_secoff +
				 i * dof->dofh_secsize);

			if (sec->dofs_type != DOF_SECT_PROVIDER)
				continue;

			if (dtrace_helper_provider_validate(dof, sec) != 0) {
				dtrace_enabling_destroy(enab);
				dtrace_dof_destroy(dof);
				return -1;
			}

			nprovs++;
		}
	}

	/*
	 * Now we need to walk through the ECB descriptions in the enabling.
	 */
	for (i = 0; i < enab->dten_ndesc; i++) {
		struct dtrace_ecbdesc	*ep = enab->dten_desc[i];
		struct dtrace_probedesc	*desc = &ep->dted_probe;

		dt_dbg_dof("  ECB Desc %s:%s:%s:%s\n",
			   desc->dtpd_provider, desc->dtpd_mod,
			   desc->dtpd_func, desc->dtpd_name);
		if (strcmp(desc->dtpd_provider, "dtrace") != 0)
			continue;

		if (strcmp(desc->dtpd_mod, "helper") != 0)
			continue;

		if (strcmp(desc->dtpd_func, "ustack") != 0)
			continue;

		rv = dtrace_helper_action_add(DTRACE_HELPER_ACTION_USTACK, ep);
		if (rv != 0) {
			/*
			 * Adding this helper action failed -- we are now going
			 * to rip out the entire generation and return failure.
			 */
			dtrace_helper_destroygen(dth->dthps_generation);
			dtrace_enabling_destroy(enab);
			dtrace_dof_destroy(dof);
			return -1;
		}

		nhelpers++;
	}

	if (nhelpers < enab->dten_ndesc)
		dtrace_dof_error(dof, "unmatched helpers");

	gen = dth->dthps_generation++;
	dtrace_enabling_destroy(enab);

	if (dhp != NULL && nprovs > 0) {
		dt_dbg_dof("  DOF 0x%p Adding and registering providers\n",
			   dof);

		dhp->dofhp_dof = (uint64_t)(uintptr_t)dof;
		if (dtrace_helper_provider_add(dhp, gen) == 0) {
			mutex_unlock(&dtrace_lock);
			dtrace_helper_provider_register(current, dth, dhp);
			mutex_lock(&dtrace_lock);

			destroy = 0;
		}
	}

	if (destroy)
		dtrace_dof_destroy(dof);

	return gen;
}

void dtrace_helpers_destroy(struct task_struct *tsk)
{
	struct dtrace_helpers	*help;
	struct dtrace_vstate	*vstate;
	int			i;

	if (tsk->dt_task == NULL)
		return;

	mutex_lock(&dtrace_lock);

	ASSERT(tsk->dt_task->dt_helpers != NULL);
	ASSERT(dtrace_helpers > 0);

	dt_dbg_dof("Helper cleanup: PID %d\n", tsk->pid);

	help = tsk->dt_task->dt_helpers;
	vstate = &help->dthps_vstate;

	/*
	 * We're now going to lose the help from this process.
	 */
	tsk->dt_task->dt_helpers = NULL;
	dtrace_sync();

	/*
	 * Destroy the helper actions.
	 */
	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		struct dtrace_helper_action *h, *next;

		for (h = help->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;
			dtrace_helper_action_destroy(h, vstate);
			h = next;
		}
	}

	mutex_unlock(&dtrace_lock);

	/*
	 * Destroy the helper providers.
	 */
	if (help->dthps_maxprovs > 0) {
		mutex_lock(&dtrace_meta_lock);
		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);

			for (i = 0; i < help->dthps_nprovs; i++) {
				dtrace_helper_provider_remove(
					&help->dthps_provs[i]->dthp_prov,
					tsk->pid);
			}
		} else {
			mutex_lock(&dtrace_lock);
			ASSERT(help->dthps_deferred == 0 ||
			       help->dthps_next != NULL ||
			       help->dthps_prev != NULL ||
			       help == dtrace_deferred_pid);

			/*
			 * Remove the helper from the deferred list.
			 */
			if (help->dthps_next != NULL)
				help->dthps_next->dthps_prev = help->dthps_prev;
			if (help->dthps_prev != NULL)
				help->dthps_prev->dthps_next = help->dthps_next;
			if (dtrace_deferred_pid == help) {
				dtrace_deferred_pid = help->dthps_next;
				ASSERT(help->dthps_prev == NULL);
			}

			mutex_unlock(&dtrace_lock);
		}

		mutex_unlock(&dtrace_meta_lock);

		for (i = 0; i < help->dthps_nprovs; i++)
			dtrace_helper_provider_destroy(help->dthps_provs[i]);

		vfree(help->dthps_provs);
	}

	mutex_lock(&dtrace_lock);

	dtrace_vstate_fini(&help->dthps_vstate);
	vfree(help->dthps_actions);
	kfree(help);

	--dtrace_helpers;
	mutex_unlock(&dtrace_lock);
}

void dtrace_helpers_duplicate(struct task_struct *from, struct task_struct *to)
{
	struct dtrace_task		*dfrom = from->dt_task;
	struct dtrace_task		*dto = to->dt_task;
	struct dtrace_helpers		*help, *newhelp;
	struct dtrace_helper_action	*helper, *new, *last;
	struct dtrace_difo		*dp;
	struct dtrace_vstate		*vstate;

	int i, j, sz, hasprovs = 0;

	if (dfrom == NULL || dto == NULL)
		return;

	mutex_lock(&dtrace_lock);

	ASSERT(dfrom->dt_helpers != NULL);
	ASSERT(dtrace_helpers > 0);

	help = dfrom->dt_helpers;
	newhelp = dtrace_helpers_create(to);

	ASSERT(dto->dt_helpers != NULL);

	newhelp->dthps_generation = help->dthps_generation;
	vstate = &newhelp->dthps_vstate;

	/*
	 * Duplicate the helper actions.
	 */
	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		helper = help->dthps_actions[i];
		if (helper == NULL)
			continue;

		for (last = NULL; helper != NULL; helper = helper->dtha_next) {
			new = kzalloc(sizeof(struct dtrace_helper_action),
				      GFP_KERNEL);
			new->dtha_generation = helper->dtha_generation;

			dp = helper->dtha_predicate;
			if (dp != NULL) {
				dp = dtrace_difo_duplicate(dp, vstate);
				new->dtha_predicate = dp;
			}

			new->dtha_nactions = helper->dtha_nactions;
			sz = sizeof(struct dtrace_difo *) * new->dtha_nactions;
			new->dtha_actions = vmalloc(sz);

			for (j = 0; j < new->dtha_nactions; j++) {
				struct dtrace_difo *dp;

				dp = helper->dtha_actions[j];
				ASSERT(dp != NULL);

				dp = dtrace_difo_duplicate(dp, vstate);
				new->dtha_actions[j] = dp;
			}

			if (last != NULL)
				last->dtha_next = new;
			else
				newhelp->dthps_actions[i] = new;

			last = new;
		}
	}

	/*
	 * Duplicate the helper providers and register them with the
	 * DTrace framework.
	 */
	if (help->dthps_nprovs > 0) {
		newhelp->dthps_nprovs = help->dthps_nprovs;
		newhelp->dthps_maxprovs = help->dthps_nprovs;
		newhelp->dthps_provs = vmalloc(
			newhelp->dthps_nprovs *
			sizeof(struct dtrace_helper_provider *));

		for (i = 0; i < newhelp->dthps_nprovs; i++) {
			newhelp->dthps_provs[i] = help->dthps_provs[i];
			newhelp->dthps_provs[i]->dthp_ref++;
		}

		hasprovs = 1;
	}

	mutex_unlock(&dtrace_lock);

	if (hasprovs)
		dtrace_helper_provider_register(to, newhelp, NULL);
}

int dtrace_helper_destroygen(int gen)
{
	struct task_struct	*p = current;
	struct dtrace_helpers	*dth;
	struct dtrace_vstate	*vstate;
	int			i;

	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (current->dt_task == NULL)
		return -ENOMEM;

	dth = current->dt_task->dt_helpers;

	if (dth == NULL || gen > dth->dthps_generation)
		return -EINVAL;

	vstate = &dth->dthps_vstate;

	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		struct dtrace_helper_action *last = NULL, *h, *next;

		for (h = dth->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;

			dt_dbg_dof("  Comparing action (agen %d vs rgen %d)\n",
				   h->dtha_generation, gen);

			if (h->dtha_generation == gen) {
				if (last != NULL)
					last->dtha_next = next;
				else
					dth->dthps_actions[i] = next;

				dtrace_helper_action_destroy(h, vstate);
			} else
				last = h;
		}
	}

	/*
	 * Iterate until we've cleared out all helper providers with the given
	 * generation number.
	 */
	for (;;) {
		struct dtrace_helper_provider	*prov = NULL;

		/*
		 * Look for a helper provider with the right generation.  We
		 * have to start back at the beginning of the list each time
		 * because we drop dtrace_lock.  It's unlikely that we'll make
		 * more than two passes.
		 */
		for (i = 0; i < dth->dthps_nprovs; i++) {
			prov = dth->dthps_provs[i];

			if (prov->dthp_generation == gen)
				break;
		}

		/*
		 * If there were no matches, we are done.
		 */
		if (i == dth->dthps_nprovs)
			break;

		dt_dbg_dof("  Found provider with gen %d\n", gen);

		/*
		 * Move the last helper provider into this slot.
		 */
		dth->dthps_nprovs--;
		dth->dthps_provs[i] = dth->dthps_provs[dth->dthps_nprovs];
		dth->dthps_provs[dth->dthps_nprovs] = NULL;

		mutex_unlock(&dtrace_lock);

		/*
		 * If we have a meta provider, remove this helper provider.
		 */
		mutex_lock(&dtrace_meta_lock);

		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);

			dtrace_helper_provider_remove(&prov->dthp_prov,
						      p->pid);
		}

		mutex_unlock(&dtrace_meta_lock);

		dtrace_helper_provider_destroy(prov);

		mutex_lock(&dtrace_lock);
	}

	return 0;
}

static void dtrace_helper_trace(struct dtrace_helper_action *helper,
				struct dtrace_mstate *mstate,
				struct dtrace_vstate *vstate, int where)
{
	uint32_t		size, next, nnext, i;
	struct dtrace_helptrace	*ent;
	uint16_t		flags = this_cpu_core->cpuc_dtrace_flags;

	if (!dtrace_helptrace_enabled)
		return;

	ASSERT(vstate->dtvs_nlocals <= dtrace_helptrace_nlocals);

	/*
	 * What would a tracing framework be without its own tracing
	 * framework?  (Well, a hell of a lot simpler, for starters...)
	 */
	size = sizeof(struct dtrace_helptrace) + dtrace_helptrace_nlocals *
	       sizeof(uint64_t) - sizeof(uint64_t);

	/*
	 * Iterate until we can allocate a slot in the trace buffer.
	 */
	do {
		next = dtrace_helptrace_next;

		if (next + size < dtrace_helptrace_bufsize)
			nnext = next + size;
		else
			nnext = size;
	} while (cmpxchg(&dtrace_helptrace_next, next, nnext) != next);

	/*
	 * We have our slot; fill it in.
	 */
	if (nnext == size)
		next = 0;

	ent = (struct dtrace_helptrace *)&dtrace_helptrace_buffer[next];
	ent->dtht_helper = helper;
	ent->dtht_where = where;
	ent->dtht_nlocals = vstate->dtvs_nlocals;

	ent->dtht_fltoffs = (mstate->dtms_present & DTRACE_MSTATE_FLTOFFS)
				?  mstate->dtms_fltoffs
				: -1;
	ent->dtht_fault = DTRACE_FLAGS2FLT(flags);
	ent->dtht_illval = this_cpu_core->cpuc_dtrace_illval;

	for (i = 0; i < vstate->dtvs_nlocals; i++) {
		struct dtrace_statvar	*svar;

		svar = vstate->dtvs_locals[i];
		if (svar == NULL)
			continue;

		ASSERT(svar->dtsv_size >= NR_CPUS * sizeof(uint64_t));
		ent->dtht_locals[i] =
			((uint64_t *)(uintptr_t)svar->dtsv_data)[
							smp_processor_id()];
	}
}

uint64_t dtrace_helper(int which, struct dtrace_mstate *mstate,
		       struct dtrace_state *state, uint64_t arg0,
		       uint64_t arg1)
{
	uint16_t		*flags = &this_cpu_core->cpuc_dtrace_flags;
	uint64_t		sarg0 = mstate->dtms_arg[0];
	uint64_t		sarg1 = mstate->dtms_arg[1];
	uint64_t		rval = 0;
	struct dtrace_helpers	*helpers;
	struct dtrace_helper_action *helper;
	struct dtrace_vstate	*vstate;
	struct dtrace_difo	*pred;
	int			i, trace = dtrace_helptrace_enabled;

	ASSERT(which >= 0 && which < DTRACE_NHELPER_ACTIONS);

	if (current->dt_task == NULL)
		return 0;

	helpers = current->dt_task->dt_helpers;
	if (helpers == NULL)
		return 0;

	helper = helpers->dthps_actions[which];
	if (helper == NULL)
		return 0;

	vstate = &helpers->dthps_vstate;
	mstate->dtms_arg[0] = arg0;
	mstate->dtms_arg[1] = arg1;

	/*
	 * Now iterate over each helper.  If its predicate evaluates to 'true',
	 * we'll call the corresponding actions.  Note that the below calls
	 * to dtrace_dif_emulate() may set faults in machine state.  This is
	 * okay:  our caller (the outer dtrace_dif_emulate()) will simply plow
	 * the stored DIF offset with its own (which is the desired behavior).
	 * Also, note the calls to dtrace_dif_emulate() may allocate scratch
	 * from machine state; this is okay, too.
	 */
	for (; helper != NULL; helper = helper->dtha_next) {
		pred = helper->dtha_predicate;
		if (pred != NULL) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate, 0);

			if (!dtrace_dif_emulate(pred, mstate, vstate, state))
				goto next;

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

		for (i = 0; i < helper->dtha_nactions; i++) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate,
						    i + 1);

			rval = dtrace_dif_emulate(helper->dtha_actions[i],
						  mstate, vstate, state);

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

next:
		if (trace)
			dtrace_helper_trace(helper, mstate, vstate,
					    DTRACE_HELPTRACE_NEXT);
	}

	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_DONE);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return rval;

err:
	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
				    DTRACE_HELPTRACE_ERR);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return 0;
}
