/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_dev.c
 * DESCRIPTION:	DTrace - Framework device driver
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

#include <linux/delay.h>
#include <dtrace/types.h>
#include <linux/dtrace/ioctl.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include "ctf_api.h"
#include "dtrace.h"
#include "dtrace_dev.h"

extern char			*dtrace_helptrace_buffer;
extern int			dtrace_helptrace_bufsize;
extern int			dtrace_helptrace_enabled;

int				dtrace_opens;
int				dtrace_err_verbose;

struct dtrace_pops		dtrace_provider_ops = {
	(void (*)(void *, const struct dtrace_probedesc *))dtrace_nullop,
	(void (*)(void *, struct module *))dtrace_nullop,
	(int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	NULL,
	NULL,
	NULL,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, struct module *))dtrace_nullop,
};

static size_t			dtrace_retain_max = 1024;

struct dtrace_toxrange		*dtrace_toxrange;
int				dtrace_toxranges;
static int			dtrace_toxranges_max;

struct kmem_cache		*dtrace_state_cachep;

struct user_namespace		*init_user_namespace;

static struct dtrace_pattr	dtrace_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

DEFINE_MUTEX(dtrace_lock);

void dtrace_nullop(void)
{
}

int dtrace_enable_nullop(void)
{
	return 0;
}


#ifdef CONFIG_DT_DEBUG
static void dtrace_ioctl_sizes(void)
{
#define DBG_PRINT(x) dt_dbg_ioctl("Size of %s: %lx\n", #x, sizeof(x))
	DBG_PRINT(struct dtrace_providerdesc);
	DBG_PRINT(struct dtrace_probedesc);
	DBG_PRINT(struct dtrace_bufdesc);
	DBG_PRINT(struct dtrace_eprobedesc);
	DBG_PRINT(struct dtrace_argdesc);
	DBG_PRINT(struct dtrace_conf);
	DBG_PRINT(struct dtrace_status);
	DBG_PRINT(processorid_t);
	DBG_PRINT(struct dtrace_aggdesc);
	DBG_PRINT(struct dtrace_fmtdesc);
	DBG_PRINT(struct dof_hdr);
#undef DBG_PRINT
}

#endif

static int dtrace_open(struct inode *inode, struct file *file)
{
	struct dtrace_state	*state;
	uint32_t		priv;
	kuid_t			uid;

	dtrace_cred2priv(file->f_cred, &priv, &uid);
	if (priv == DTRACE_PRIV_NONE)
		return -EACCES;

#ifdef CONFIG_DT_DEBUG
	dtrace_ioctl_sizes();
#endif
	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);
	dtrace_probe_provide(NULL, NULL);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * Do not let a consumer continue if it is not possible to enable
	 * DTrace.
	 */
	if (dtrace_enable() != 0) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&cpu_lock);
		return -EBUSY;
	}

	dtrace_opens++;
	dtrace_membar_producer();

	state = dtrace_state_create(file);
	mutex_unlock(&cpu_lock);

	if (state == NULL) {
		if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
			dtrace_disable();
		mutex_unlock(&dtrace_lock);

		return -EAGAIN;
	}

	file->private_data = state;
	mutex_unlock(&dtrace_lock);

	return 0;
}

static long dtrace_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct dtrace_state 	*state;
	int 			rval;
	void __user		*argp = (void __user *)arg;

	state = (struct dtrace_state *) file->private_data;
	if (state->dts_anon) {
		ASSERT(dtrace_anon.dta_state == NULL);
		state = state->dts_anon;
	}

	switch (cmd) {
	case DTRACEIOC_PROVIDER: {
		struct dtrace_providerdesc	pvd;
		struct dtrace_provider		*pvp;

		dt_dbg_ioctl("IOCTL PROVIDER (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&pvd, argp, sizeof(pvd)) != 0)
			return -EFAULT;

		pvd.dtvd_name[DTRACE_PROVNAMELEN - 1] = '\0';
		mutex_lock(&dtrace_provider_lock);

		for (pvp = dtrace_provider; pvp != NULL; pvp = pvp->dtpv_next) {
			if (strcmp(pvp->dtpv_name, pvd.dtvd_name) == 0)
				break;
		}

		mutex_unlock(&dtrace_provider_lock);

		dt_dbg_ioctl("  Provider '%s' %sfound\n",
			     pvd.dtvd_name, pvp ? "" : "not ");
		if (pvp == NULL)
			return -ESRCH;

		memcpy(&pvd.dtvd_priv, &pvp->dtpv_priv,
		       sizeof(struct dtrace_ppriv));
		memcpy(&pvd.dtvd_attr, &pvp->dtpv_attr,
		       sizeof(struct dtrace_pattr));

		if (copy_to_user(argp, &pvd, sizeof(pvd)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_EPROBE: {
		struct dtrace_eprobedesc epdesc;
		struct dtrace_ecb	*ecb;
		struct dtrace_action	*act;
		void			*buf;
		size_t			size;
		uint8_t			*dest;
		int			nrecs;

		dt_dbg_ioctl("IOCTL EPROBE (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&epdesc, argp, sizeof(epdesc)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		ecb = dtrace_epid2ecb(state, epdesc.dtepd_epid);
		if (ecb == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		if (ecb->dte_probe == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		epdesc.dtepd_probeid = ecb->dte_probe->dtpr_id;
		epdesc.dtepd_uarg = ecb->dte_uarg;
		epdesc.dtepd_size = ecb->dte_size;

		nrecs = epdesc.dtepd_nrecs;
		epdesc.dtepd_nrecs = 0;
		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			epdesc.dtepd_nrecs++;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copy_to_user(), below.
		 */
		size = sizeof(struct dtrace_eprobedesc) +
		       (epdesc.dtepd_nrecs * sizeof(struct dtrace_recdesc));

		buf = vmalloc(size);
		if (buf == NULL)
			return -ENOMEM;

		dest = buf;
		memcpy(dest, &epdesc, sizeof(epdesc));
		dest += offsetof(struct dtrace_eprobedesc, dtepd_rec[0]);

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			if (nrecs-- == 0)
				break;

			memcpy(dest, &act->dta_rec,
			       sizeof(struct dtrace_recdesc));
			dest += sizeof(struct dtrace_recdesc);
		}

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, buf,
				 (uintptr_t)(dest - (uint8_t *)buf)) != 0) {
			vfree(buf);
			return -EFAULT;
		}

		vfree(buf);
		return 0;
	}

	case DTRACEIOC_AGGDESC: {
		struct dtrace_aggdesc	aggdesc;
		struct dtrace_action	*act;
		struct dtrace_aggregation *agg;
		int			nrecs;
		uint32_t		offs;
		struct dtrace_recdesc	*lrec;
		void			*buf;
		size_t			size;
		uint8_t			*dest;

		dt_dbg_ioctl("IOCTL AGGDESC (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&aggdesc, argp, sizeof(aggdesc)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		agg = dtrace_aggid2agg(state, aggdesc.dtagd_id);
		if (agg == NULL) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		aggdesc.dtagd_epid = agg->dtag_ecb->dte_epid;

		nrecs = aggdesc.dtagd_nrecs;
		aggdesc.dtagd_nrecs = 0;

		offs = agg->dtag_base;
		lrec = &agg->dtag_action.dta_rec;
		aggdesc.dtagd_size = lrec->dtrd_offset + lrec->dtrd_size -
				     offs;

		for (act = agg->dtag_first; ; act = act->dta_next) {
			ASSERT(act->dta_intuple ||
			       DTRACEACT_ISAGG(act->dta_kind));

			/*
			 * If this action has a record size of zero, it
			 * denotes an argument to the aggregating action.
			 * Because the presence of this record doesn't (or
			 * shouldn't) affect the way the data is interpreted,
			 * we don't copy it out to save user-level the
			 * confusion of dealing with a zero-length record.
			 */
			if (act->dta_rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			aggdesc.dtagd_nrecs++;

			if (act == &agg->dtag_action)
				break;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof(struct dtrace_aggdesc) +
		       (aggdesc.dtagd_nrecs * sizeof(struct dtrace_recdesc));

		buf = vmalloc(size);
		if (buf == NULL)
			return -ENOMEM;

		dest = buf;
		memcpy(dest, &aggdesc, sizeof(aggdesc));
		dest += offsetof(struct dtrace_aggdesc, dtagd_rec[0]);

		for (act = agg->dtag_first; ; act = act->dta_next) {
			struct dtrace_recdesc	rec = act->dta_rec;

			/*
			 * See the comment in the above loop for why we pass
			 * over zero-length records.
			 */
			if (rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			if (nrecs-- == 0)
				break;

			rec.dtrd_offset -= offs;
			memcpy(dest, &rec, sizeof(rec));
			dest += sizeof(struct dtrace_recdesc);

			if (act == &agg->dtag_action)
				break;
		}

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, buf,
				 (uintptr_t)(dest - (uint8_t *)buf)) != 0) {
			vfree(buf);
			return -EFAULT;
		}

		vfree(buf);
		return 0;
	}

	case DTRACEIOC_ENABLE: {
		struct dof_hdr		*dof;
		struct dtrace_enabling	*enab = NULL;
		struct dtrace_vstate	*vstate;
		int			err = 0;
		int			rv;

		dt_dbg_ioctl("IOCTL ENABLE (cmd %#x), argp %p\n", cmd, argp);

		rv = 0;

		/*
		 * If a NULL argument has been passed, we take this as our
		 * cue to reevaluate our enablings.
		 */
		if (argp == NULL) {
			dtrace_enabling_matchall();

			return 0;
		}

		dof = dtrace_dof_copyin(argp, &rval);
		if (dof == NULL)
			return rval;

		mutex_lock(&cpu_lock);
		mutex_lock(&dtrace_lock);
		vstate = &state->dts_vstate;

		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return -EBUSY;
		}

		if (dtrace_dof_slurp(dof, vstate, file->f_cred, &enab, 0,
				     TRUE) != 0) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return -EINVAL;
		}

		rval = dtrace_dof_options(dof, state);
		if (rval != 0) {
			dtrace_enabling_destroy(enab);
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return rval;
		}

		err = dtrace_enabling_match(enab, &rv);
		if (err == 0)
			err = dtrace_enabling_retain(enab);
		else
			dtrace_enabling_destroy(enab);

		mutex_unlock(&dtrace_lock);
		mutex_unlock(&cpu_lock);
		dtrace_dof_destroy(dof);

		return err == 0 ? rv : err;
	}

	case DTRACEIOC_REPLICATE: {
		struct dtrace_repldesc	desc;
		struct dtrace_probedesc	*match = &desc.dtrpd_match;
		struct dtrace_probedesc	*create = &desc.dtrpd_create;
		int			err;

		dt_dbg_ioctl("IOCTL REPLICATE (cmd %#x), argp %p\n",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		match->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		match->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		match->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		match->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		create->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		create->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		create->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		create->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		mutex_lock(&dtrace_lock);
		err = dtrace_enabling_replicate(state, match, create);
		mutex_unlock(&dtrace_lock);

		return err;
	}

	case DTRACEIOC_PROBEMATCH:
	case DTRACEIOC_PROBES: {
		int			id;
		struct dtrace_probe	*probe = NULL;
		struct dtrace_probedesc	desc;
		struct dtrace_probekey	pkey;
		uint32_t		priv;
		kuid_t			uid;

		dt_dbg_ioctl("IOCTL %s (cmd %#x), argp %p\n",
			     cmd == DTRACEIOC_PROBES ? "PROBES"
						     : "PROBEMATCH",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		desc.dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		desc.dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		desc.dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		desc.dtpd_name[DTRACE_NAMELEN - 1] = '\0';
		dt_dbg_ioctl("  Probe ID %d %s:%s:%s:%s\n",
			     desc.dtpd_id, desc.dtpd_provider, desc.dtpd_mod,
			     desc.dtpd_func, desc.dtpd_name);

		/*
		 * Before we attempt to match this probe, we want to give
		 * all providers the opportunity to provide it.
		 */
		if (desc.dtpd_id == DTRACE_IDNONE) {
			mutex_lock(&module_mutex);
			mutex_lock(&dtrace_provider_lock);
			dtrace_probe_provide(&desc, NULL);
			mutex_unlock(&dtrace_provider_lock);
			mutex_unlock(&module_mutex);
		}

		if (cmd == DTRACEIOC_PROBEMATCH)  {
			dtrace_probekey(&desc, &pkey);
			pkey.dtpk_id = DTRACE_IDNONE;
		}

		dtrace_cred2priv(file->f_cred, &priv, &uid);

		mutex_lock(&dtrace_lock);

		id = desc.dtpd_id;
		if (cmd == DTRACEIOC_PROBEMATCH)  {
			int	m = 0;

			while ((probe = dtrace_probe_get_next(&id))
			       != NULL) {
				m = dtrace_match_probe(probe, &pkey, priv, uid);
				if (m)
					break;

				id++;
			}

			if (m < 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		} else {
			while ((probe = dtrace_probe_get_next(&id))
			       != NULL) {
				if (dtrace_match_priv(probe, priv, uid))
					break;

				id++;
			}
		}

		if (probe == NULL) {
			mutex_unlock(&dtrace_lock);
			return -ESRCH;
		}

		dtrace_probe_description(probe, &desc);
		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_PROBEARG: {
		struct dtrace_argdesc	desc;
		struct dtrace_probe	*probe;
		struct dtrace_provider	*prov;

		dt_dbg_ioctl("IOCTL PROBEARG (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		if (desc.dtargd_id == DTRACE_IDNONE)
			return -EINVAL;

		if (desc.dtargd_ndx == DTRACE_ARGNONE)
			return -EINVAL;

		mutex_lock(&module_mutex);
		mutex_lock(&dtrace_provider_lock);
		mutex_lock(&dtrace_lock);

		probe = dtrace_probe_lookup_id(desc.dtargd_id);
		if (probe == NULL) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&dtrace_provider_lock);
			mutex_unlock(&module_mutex);

			return -EINVAL;
		}

		mutex_unlock(&dtrace_lock);

		prov = probe->dtpr_provider;

		if (prov->dtpv_pops.dtps_getargdesc == NULL) {
			/*
			 * There isn't any typed information for this probe.
			 * Set the argument number to DTRACE_ARGNONE.
			 */
			desc.dtargd_ndx = DTRACE_ARGNONE;
		} else {
			desc.dtargd_native[0] = '\0';
			desc.dtargd_xlate[0] = '\0';
			desc.dtargd_mapping = desc.dtargd_ndx;

			prov->dtpv_pops.dtps_getargdesc(
				prov->dtpv_arg, probe->dtpr_id,
				probe->dtpr_arg, &desc);
		}

		mutex_unlock(&dtrace_provider_lock);
		mutex_unlock(&module_mutex);

		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_GO: {
		processorid_t	cpuid;

		dt_dbg_ioctl("IOCTL GO (cmd %#x), argp %p\n", cmd, argp);

		rval = dtrace_state_go(state, &cpuid);

		if (rval != 0)
			return rval;

		if (copy_to_user(argp, &cpuid, sizeof(cpuid)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_STOP: {
		processorid_t	cpuid;

		dt_dbg_ioctl("IOCTL STOP (cmd %#x), argp %p\n", cmd, argp);

		mutex_lock(&dtrace_lock);
		rval = dtrace_state_stop(state, &cpuid);
		mutex_unlock(&dtrace_lock);

		if (rval != 0)
			return rval;

		if (copy_to_user(argp, &cpuid, sizeof(cpuid)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_DOFGET: {
		struct dof_hdr	hdr, *dof;
		uint64_t	len;

		dt_dbg_ioctl("IOCTL DOFGET (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&hdr, argp, sizeof(hdr)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);
		dof = dtrace_dof_create(state);
		mutex_unlock(&dtrace_lock);
		if (dof == NULL)
			return -ENOMEM;

		len = min(hdr.dofh_loadsz, dof->dofh_loadsz);
		rval = copy_to_user(argp, dof, len);
		dtrace_dof_destroy(dof);

		return rval == 0 ? 0 : -EFAULT;
	}

	case DTRACEIOC_AGGSNAP:
	case DTRACEIOC_BUFSNAP: {
		struct dtrace_bufdesc	desc;
		caddr_t			cached;
		struct dtrace_buffer	*buf;

		dt_dbg_ioctl("IOCTL %s (cmd %#x), argp %p\n",
			     cmd == DTRACEIOC_AGGSNAP ? "AGGSNAP"
						      : "BUFSNAP",
			     cmd, argp);

		if (copy_from_user(&desc, argp, sizeof(desc)) != 0)
			return -EFAULT;

		if (desc.dtbd_cpu < 0 || desc.dtbd_cpu >= NR_CPUS)
			return -EINVAL;

		mutex_lock(&dtrace_lock);

		if (cmd == DTRACEIOC_BUFSNAP)
			buf = &state->dts_buffer[desc.dtbd_cpu];
		else
			buf = &state->dts_aggbuffer[desc.dtbd_cpu];

		if (buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL)) {
			size_t	sz = buf->dtb_offset;

			if (state->dts_activity != DTRACE_ACTIVITY_STOPPED) {
				mutex_unlock(&dtrace_lock);
				return -EBUSY;
			}

			/*
			 * If this buffer has already been consumed, we're
			 * going to indicate that there's nothing left here
			 * to consume.
			 */
			if (buf->dtb_flags & DTRACEBUF_CONSUMED) {
				mutex_unlock(&dtrace_lock);

				desc.dtbd_size = 0;
				desc.dtbd_drops = 0;
				desc.dtbd_errors = 0;
				desc.dtbd_oldest = 0;
				sz = sizeof(desc);

				if (copy_to_user(argp, &desc, sz) != 0)
					return -EFAULT;

				return 0;
			}

			/*
			 * If this is a ring buffer that has wrapped, we want
			 * to copy the whole thing out.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				dtrace_buffer_polish(buf);
				sz = buf->dtb_size;
			}

			if (copy_to_user(desc.dtbd_data, buf->dtb_tomax,
					 sz) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EFAULT;
			}

			desc.dtbd_size = sz;
			desc.dtbd_drops = buf->dtb_drops;
			desc.dtbd_errors = buf->dtb_errors;
			desc.dtbd_oldest = buf->dtb_xamot_offset;

			mutex_unlock(&dtrace_lock);

			if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
				return -EFAULT;

			buf->dtb_flags |= DTRACEBUF_CONSUMED;

			return 0;
		}

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		cached = buf->dtb_tomax;

		dtrace_xcall(desc.dtbd_cpu,
			     (dtrace_xcall_t)dtrace_buffer_switch, buf);

		state->dts_errors += buf->dtb_xamot_errors;

		/*
		 * If the buffers did not actually switch, then the cross call
		 * did not take place -- presumably because the given CPU is
		 * not in the ready set.  If this is the case, we'll return
		 * ENOENT.
		 */
		if (buf->dtb_tomax == cached) {
			ASSERT(buf->dtb_xamot != cached);
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		ASSERT(cached == buf->dtb_xamot);

		/*
		 * We have our snapshot; now copy it out.
		 */
		if (copy_to_user(desc.dtbd_data, buf->dtb_xamot,
				 buf->dtb_xamot_offset) != 0) {
			mutex_unlock(&dtrace_lock);
			return -EFAULT;
		}

		desc.dtbd_size = buf->dtb_xamot_offset;
		desc.dtbd_drops = buf->dtb_xamot_drops;
		desc.dtbd_errors = buf->dtb_xamot_errors;
		desc.dtbd_oldest = 0;

		mutex_unlock(&dtrace_lock);

		/*
		 * Finally, copy out the buffer description.
		 */
		if (copy_to_user(argp, &desc, sizeof(desc)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_CONF: {
		struct dtrace_conf	conf;

		dt_dbg_ioctl("IOCTL CONF (cmd %#x), argp %p\n", cmd, argp);

		memset(&conf, 0, sizeof(conf));
		conf.dtc_difversion = DIF_VERSION;
		conf.dtc_difintregs = DIF_DIR_NREGS;
		conf.dtc_diftupregs = DIF_DTR_NREGS;
		conf.dtc_ctfmodel = CTF_MODEL_NATIVE;
		conf.dtc_maxbufs = nr_cpu_ids;

		if (copy_to_user(argp, &conf, sizeof(conf)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_STATUS: {
		struct dtrace_status	stat;
		struct dtrace_dstate	*dstate;
		int			i, j;
		uint64_t		nerrs;

		dt_dbg_ioctl("IOCTL STATUS (cmd %#x), argp %p\n", cmd, argp);

		/*
		 * See the comment in dtrace_state_deadman() for the reason
		 * for setting dts_laststatus to UINT64_MAX before setting
		 * it to the correct value.
		 */
		state->dts_laststatus = ns_to_ktime(UINT64_MAX);
		dtrace_membar_producer();
		state->dts_laststatus = dtrace_gethrtime();

		memset(&stat, 0, sizeof(stat));

		mutex_lock(&dtrace_lock);

		if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
			mutex_unlock(&dtrace_lock);
			return -ENOENT;
		}

		if (state->dts_activity == DTRACE_ACTIVITY_DRAINING)
			stat.dtst_exiting = 1;

		nerrs = state->dts_errors;
		dstate = &state->dts_vstate.dtvs_dynvars;

		for (i = 0; i < NR_CPUS; i++) {
			struct dtrace_dstate_percpu *dcpu;

			dcpu = &dstate->dtds_percpu[i];
			stat.dtst_dyndrops += dcpu->dtdsc_drops;
			stat.dtst_dyndrops_dirty += dcpu->dtdsc_dirty_drops;
			stat.dtst_dyndrops_rinsing += dcpu->dtdsc_rinsing_drops;

			if (state->dts_buffer[i].dtb_flags & DTRACEBUF_FULL)
				stat.dtst_filled++;

			nerrs += state->dts_buffer[i].dtb_errors;

			for (j = 0; j < state->dts_nspeculations; j++) {
				struct dtrace_speculation	*spec;
				struct dtrace_buffer		*buf;

				spec = &state->dts_speculations[j];
				buf = &spec->dtsp_buffer[i];
				stat.dtst_specdrops += buf->dtb_xamot_drops;
			}
		}

		stat.dtst_specdrops_busy = state->dts_speculations_busy;
		stat.dtst_specdrops_unavail = state->dts_speculations_unavail;
		stat.dtst_stkstroverflows = state->dts_stkstroverflows;
		stat.dtst_dblerrors = state->dts_dblerrors;
		stat.dtst_killed = (state->dts_activity ==
				    DTRACE_ACTIVITY_KILLED);
		stat.dtst_errors = nerrs;

		mutex_unlock(&dtrace_lock);

		if (copy_to_user(argp, &stat, sizeof(stat)) != 0)
			return -EFAULT;

		return 0;
	}

	case DTRACEIOC_FORMAT: {
		struct dtrace_fmtdesc	fmt;
		char			*str;
		int			len;

		dt_dbg_ioctl("IOCTL FORMAT (cmd %#x), argp %p\n", cmd, argp);

		if (copy_from_user(&fmt, argp, sizeof(fmt)) != 0)
			return -EFAULT;

		mutex_lock(&dtrace_lock);

		if (fmt.dtfd_format == 0 ||
		    fmt.dtfd_format > state->dts_nformats) {
			mutex_unlock(&dtrace_lock);
			return -EINVAL;
		}

		/*
		 * Format strings are allocated contiguously and they are
		 * never freed; if a format index is less than the number
		 * of formats, we can assert that the format map is non-NULL
		 * and that the format for the specified index is non-NULL.
		 */
		ASSERT(state->dts_formats != NULL);
		str = state->dts_formats[fmt.dtfd_format - 1];
		ASSERT(str != NULL);

		len = strlen(str) + 1;

		if (len > fmt.dtfd_length) {
			fmt.dtfd_length = len;

			if (copy_to_user(argp, &fmt, sizeof(fmt)) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		} else {
			if (copy_to_user(fmt.dtfd_string, str, len) != 0) {
				mutex_unlock(&dtrace_lock);
				return -EINVAL;
			}
		}

		mutex_unlock(&dtrace_lock);

		return 0;
	}

	default:
		dt_dbg_ioctl("IOCTL ??? (cmd %#x), argp %p\n",
			     cmd, argp);
		break;
	}

	return -ENOTTY;
}

static int dtrace_close(struct inode *inode, struct file *file)
{
	struct dtrace_state	*state = file->private_data;

	mutex_lock(&cpu_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * If there is anonymous state, destroy that first.
	 */
	if (state->dts_anon) {
		ASSERT(dtrace_anon.dta_state == NULL);
		dtrace_state_destroy(state->dts_anon);
	}

	dtrace_state_destroy(state);
	ASSERT(dtrace_opens > 0);

	if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
		dtrace_disable();

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&cpu_lock);

	return 0;
}

static int dtrace_helper_open(struct inode *inode, struct file *file)
{
	return 0;
}

static long dtrace_helper_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	int		rval;
	struct dof_helper help, *dhp = NULL;
	void __user	*argp = (void __user *)arg;

	switch (cmd) {
	case DTRACEHIOC_ADDDOF:
		dt_dbg_ioctl("Helper IOCTL ADDDOF (cmd %#x), argp %p\n",
			     cmd, argp);

		if (copy_from_user(&help, argp, sizeof(help)) != 0) {
			dtrace_dof_error(NULL, "failed to copy DOF helper");
			return -EFAULT;
		}

		dhp = &help;
		argp = (void __user *)help.dofhp_dof;

		fallthrough;

	case DTRACEHIOC_ADD: {
		struct dof_hdr	*dof = dtrace_dof_copyin(argp, &rval);

		if (dof == NULL)
			return rval;

		if (cmd == DTRACEHIOC_ADD)
			dt_dbg_ioctl("Helper IOCTL ADD (cmd %#x), argp %p\n",
				     cmd, argp);

		mutex_lock(&dtrace_lock);

		/*
		 * The dtrace_helper_slurp() routine takes responsibility for
		 * the dof -- it may free it now, or it may save it and free it
		 * later.
		 */
		rval = dtrace_helper_slurp(dof, dhp);
		if (rval == -1)
			rval = -EINVAL;

		mutex_unlock(&dtrace_lock);

		dt_dbg_ioctl("Helper IOCTL %s returning %d\n",
			     cmd == DTRACEHIOC_ADD ? "ADD"
						   : "ADDDOF",
			     rval);

		return rval;
	}

	case DTRACEHIOC_REMOVE:
		dt_dbg_ioctl("Helper IOCTL REMOVE (cmd %#x), argp %p\n",
			     cmd, argp);

		mutex_lock(&dtrace_lock);

		rval = dtrace_helper_destroygen((uintptr_t)argp);

		mutex_unlock(&dtrace_lock);

		dt_dbg_ioctl("Helper IOCTL REMOVE returning %d\n", rval);

		return rval;
	default:
		dt_dbg_ioctl("Helper IOCTL ??? (cmd %#x), argp %p\n",
			     cmd, argp);
		break;
	}

	return -ENOTTY;
}

static int dtrace_helper_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dtrace_fops = {
	.owner  = THIS_MODULE,
	.unlocked_ioctl = dtrace_ioctl,
	.open   = dtrace_open,
	.release = dtrace_close,
};

static const struct file_operations helper_fops = {
	.owner  = THIS_MODULE,
	.unlocked_ioctl = dtrace_helper_ioctl,
	.compat_ioctl = dtrace_helper_ioctl,
	.open   = dtrace_helper_open,
	.release = dtrace_helper_close,
};

static struct miscdevice dtrace_dev = {
	.minor = DT_DEV_DTRACE_MINOR,
	.name = "dtrace",
	.nodename = "dtrace/dtrace",
	.fops = &dtrace_fops,
};

static struct miscdevice helper_dev = {
	.minor = DT_DEV_HELPER_MINOR,
	.name = "helper",
	.nodename = "dtrace/helper",
	.fops = &helper_fops,
};

static void dtrace_module_loaded(struct module *mp)
{
	struct dtrace_provider *prv;

	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);

	/*
	 * Give all providers a chance to register probes for this module.
	 */
	for (prv = dtrace_provider; prv != NULL; prv = prv->dtpv_next)
		prv->dtpv_pops.dtps_provide_module(prv->dtpv_arg, mp);

	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);

	/*
	 * If we have any retained enablings, we need to match against them.
	 */
	mutex_lock(&dtrace_lock);

	if (dtrace_retained == NULL) {
		mutex_unlock(&dtrace_lock);
		return;
	}

	mutex_unlock(&dtrace_lock);
	dtrace_enabling_matchall();
}

static void dtrace_module_unloaded(struct module *mp)
{
	struct dtrace_probe	template, *probe, *first, *next;
	struct dtrace_provider	*prv;

	template.dtpr_mod = mp->name;

	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	if (dtrace_bymod == NULL) {
		/*
		 * The DTrace module is loaded (obviously) but not attached;
		 * we don't have any work to do.
		 */
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_provider_lock);
		mutex_unlock(&module_mutex);
		return;
	}

	for (probe = first = dtrace_hash_lookup(dtrace_bymod, &template);
	     probe != NULL; probe = probe->dtpr_nextmod) {
		if (probe->dtpr_ecb != NULL) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&dtrace_provider_lock);
			mutex_unlock(&module_mutex);

			/*
			 * This shouldn't _actually_ be possible -- we're
			 * unloading a module that has an enabled probe in it.
			 * (It's normally up to the provider to make sure that
			 * this can't happen.)  However, because dtps_enable()
			 * doesn't have a failure mode, there can be an
			 * enable/unload race.  Upshot:  we don't want to
			 * assert, but we're not going to disable the
			 * probe, either.
			 */
			if (dtrace_err_verbose) {
				pr_warn("unloaded module '%s' "
					"had enabled probes", mp->name);
			}

			return;
		}
	}

	probe = first;

	for (first = NULL; probe != NULL; probe = next) {
		dtrace_probe_remove_id(probe->dtpr_id);

		next = probe->dtpr_nextmod;
		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		if (first == NULL) {
			first = probe;
			probe->dtpr_nextmod = NULL;
		} else {
			probe->dtpr_nextmod = first;
			first = probe;
		}
	}

	/*
	 * We've removed all of the module's probes from the hash chains and
	 * from the probe array.  Now issue a dtrace_sync() to be sure that
	 * everyone has cleared out from any probe array processing.
	 */
	dtrace_sync();

	for (probe = first; probe != NULL; probe = first) {
		first = probe->dtpr_nextmod;
		prv = probe->dtpr_provider;
		prv->dtpv_pops.dtps_destroy(prv->dtpv_arg, probe->dtpr_id,
		    probe->dtpr_arg);
		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
		kfree(probe);
	}

	/*
	 * Notify providers to cleanup per-module data for this module.
	 */
	for (prv = dtrace_provider; prv != NULL; prv = prv->dtpv_next)
		if (prv->dtpv_pops.dtps_destroy_module != NULL)
			prv->dtpv_pops.dtps_destroy_module(prv->dtpv_arg, mp);

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);
}

/*
 * Register a toxic range.
 */
static void dtrace_toxrange_add(uintptr_t base, uintptr_t limit)
{
	if (dtrace_toxranges >= dtrace_toxranges_max) {
		int			osize, nsize;
		struct dtrace_toxrange	*range;

		osize = dtrace_toxranges_max * sizeof(struct dtrace_toxrange);

		if (osize == 0) {
			ASSERT(dtrace_toxrange == NULL);
			ASSERT(dtrace_toxranges_max == 0);

			dtrace_toxranges_max = 1;
		} else
			dtrace_toxranges_max <<= 1;

		nsize = dtrace_toxranges_max * sizeof(struct dtrace_toxrange);
		range = vzalloc(nsize);
		if (range == NULL) {
			pr_warn("Failed to add toxic range: out of memory\n");
			return;
		}

		if (dtrace_toxrange != NULL) {
			ASSERT(osize != 0);

			memcpy(range, dtrace_toxrange, osize);
			vfree(dtrace_toxrange);
		}

		dtrace_toxrange = range;
	}

	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_base == (uintptr_t)NULL);
	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_limit == (uintptr_t)NULL);

	dtrace_toxrange[dtrace_toxranges].dtt_base = base;
	dtrace_toxrange[dtrace_toxranges].dtt_limit = limit;
	dtrace_toxranges++;
}

/*
 * Check if an address falls within a toxic region.
 */
int dtrace_istoxic(uintptr_t kaddr, size_t size)
{
	uintptr_t	taddr, tsize;
	int		i;

	for (i = 0; i < dtrace_toxranges; i++) {
		taddr = dtrace_toxrange[i].dtt_base;
		tsize = dtrace_toxrange[i].dtt_limit - taddr;

		if (kaddr - taddr < tsize) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			this_cpu_core->cpuc_dtrace_illval = kaddr;
			return 1;
		}

		if (taddr - kaddr < size) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			this_cpu_core->cpuc_dtrace_illval = kaddr;
			return 1;
		}
	}

	return 0;
}

static int dtrace_mod_notifier(struct notifier_block *nb, unsigned long val,
			       void *args)
{
	struct module	*mp = args;

	if (!mp)
		return NOTIFY_DONE;

	switch (val) {
	case MODULE_STATE_LIVE:
		dtrace_module_loaded(mp);
		break;

	case MODULE_STATE_GOING:
		dtrace_module_unloaded(mp);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block    dtrace_modmgmt = {
	.notifier_call = dtrace_mod_notifier,
};

/*
 * Initialize the DTrace core.
 *
 * Equivalent to: dtrace_attach()
 */
int dtrace_dev_init(void)
{
	dtrace_provider_id_t	id;
	int			rc = 0;
	struct cred		*cred;

	/*
	 * Register the device for the DTrace core.
	 */
	rc = misc_register(&dtrace_dev);
	if (rc) {
		pr_err("%s: Can't register misc device %d\n",
		       dtrace_dev.name, dtrace_dev.minor);

		return rc;
	}

	/*
	 * Register the device for the DTrace helper.
	 */
	rc = misc_register(&helper_dev);
	if (rc) {
		pr_err("%s: Can't register misc device %d\n",
		       helper_dev.name, helper_dev.minor);

		misc_deregister(&dtrace_dev);
		return rc;
	}

	mutex_lock(&cpu_lock);
	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	rc = dtrace_probe_init();
	if (rc) {
		pr_err("Failed to initialize DTrace core\n");

		goto errout;
	}

#if IS_ENABLED(CONFIG_DT_FASTTRAP)
	dtrace_helpers_cleanup = dtrace_helpers_destroy;
	dtrace_helpers_fork = dtrace_helpers_duplicate;
#endif
#ifdef FIXME
	dtrace_cpu_init = dtrace_cpu_setup_initial;
	dtrace_cpustart_init = dtrace_suspend;
	dtrace_cpustart_fini = dtrace_resume;
	dtrace_debugger_init = dtrace_suspend;
	dtrace_debugger_fini = dtrace_resume;

	register_cpu_setup_func((cpu_setup_func_t *)dtrace_cpu_setup, NULL);
#endif

#ifdef FIXME
	dtrace_taskq = taskq_create("dtrace_taskq", 1, maxclsyspri, 1, INT_MAX,
				    0);
#endif

	dtrace_state_cachep = kmem_cache_create("dtrace_state_cache",
				sizeof(struct dtrace_dstate_percpu) * NR_CPUS,
				0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	/* From now on the failures are results of failed allocations. */
	rc = -ENOMEM;

	/*
	 * Create the probe hashtables.
	 */
	dtrace_bymod = dtrace_hash_create(
				offsetof(struct dtrace_probe, dtpr_mod),
				offsetof(struct dtrace_probe, dtpr_nextmod),
				offsetof(struct dtrace_probe, dtpr_prevmod));
	if (dtrace_bymod == NULL)
		goto errout;

	dtrace_byfunc = dtrace_hash_create(
				offsetof(struct dtrace_probe, dtpr_func),
				offsetof(struct dtrace_probe, dtpr_nextfunc),
				offsetof(struct dtrace_probe, dtpr_prevfunc));
	if (dtrace_byfunc == NULL)
		goto errout;

	dtrace_byname = dtrace_hash_create(
				offsetof(struct dtrace_probe, dtpr_name),
				offsetof(struct dtrace_probe, dtpr_nextname),
				offsetof(struct dtrace_probe, dtpr_prevname));
	if (dtrace_byname == NULL)
		goto errout;

	/*
	 * Initialize cred.
	 */
	cred = prepare_kernel_cred(NULL);
	if (cred == NULL)
		goto errout;

	init_user_namespace = cred->user_ns;
	put_cred(cred);

	/*
	 * Ensure that the X configuration parameter has a legal value.
	 */
	if (dtrace_retain_max < 1) {
		pr_warn("Illegal value (%lu) for dtrace_retain_max; "
			"setting to 1", (unsigned long)dtrace_retain_max);

		dtrace_retain_max = 1;
	}

	/*
	 * Discover our toxic ranges.
	 */
	dtrace_toxic_ranges(dtrace_toxrange_add);

	/*
	 * Register ourselves as a provider.
	 */
	dtrace_register("dtrace", &dtrace_provider_attr, DTRACE_PRIV_NONE, 0,
			&dtrace_provider_ops, NULL, &id);

	ASSERT(dtrace_provider != NULL);
	ASSERT((dtrace_provider_id_t)dtrace_provider == id);

	/*
	 * Create BEGIN, END, and ERROR probes.
	 */
	dtrace_probeid_begin = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "BEGIN", 0, NULL);
	if (dtrace_probeid_begin == DTRACE_IDNONE)
		goto errout;

	dtrace_probeid_end = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "END", 0, NULL);
	if (dtrace_probeid_end == DTRACE_IDNONE)
		goto errout;

	dtrace_probeid_error = dtrace_probe_create(
				(dtrace_provider_id_t)dtrace_provider, NULL,
				NULL, "ERROR", 1, NULL);
	if (dtrace_probeid_error == DTRACE_IDNONE)
		goto errout;

	dtrace_anon_property();

	/*
	 * If DTrace helper tracing is enabled, we need to allocate a trace
	 * buffer.
	 */
	if (dtrace_helptrace_enabled) {
		ASSERT(dtrace_helptrace_buffer == NULL);

		dtrace_helptrace_buffer = vzalloc(dtrace_helptrace_bufsize);

		if (dtrace_helptrace_buffer == NULL) {
			pr_warn("Cannot allocate helptrace buffer; "
				"disabling dtrace_helptrace\n");
			dtrace_helptrace_enabled = 0;
		}
	}

#ifdef FIXME
	/*
	 * There is usually code here to handle the case where there already
	 * are providers when we get to this code.  On Linux, that does not
	 * seem to be possible since the DTrace core module (this code) is
	 * loaded as a dependency for each provider, and thus this
	 * initialization code is executed prior to the initialization code of
	 * the first provider causing the core to be loaded.
	 */
#endif

	if (register_module_notifier(&dtrace_modmgmt))
		goto errout;

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);
	mutex_unlock(&cpu_lock);

	return 0;

errout:
	if (dtrace_provider != NULL)
		(void) dtrace_unregister((dtrace_provider_id_t)dtrace_provider);

	dtrace_hash_destroy(dtrace_bymod);
	dtrace_hash_destroy(dtrace_byfunc);
	dtrace_hash_destroy(dtrace_byname);

	misc_deregister(&helper_dev);
	misc_deregister(&dtrace_dev);

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);
	mutex_unlock(&cpu_lock);

	return rc;
}

void dtrace_dev_exit(void)
{
	mutex_lock(&cpu_lock);
	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	dtrace_unregister((dtrace_provider_id_t)dtrace_provider);
	dtrace_provider = NULL;

	dtrace_probe_exit();

	unregister_module_notifier(&dtrace_modmgmt);

#if IS_ENABLED(CONFIG_DT_FASTTRAP)
	dtrace_helpers_cleanup = NULL;
	dtrace_helpers_fork = NULL;
#endif
#ifdef FIXME
	dtrace_cpu_init = NULL;
	dtrace_cpustart_init = NULL;
	dtrace_cpustart_fini = NULL;
	dtrace_debugger_init = NULL;
	dtrace_debugger_fini = NULL;

	unregister_cpu_setup_func((cpu_setup_func_t *)dtrace_cpu_setup, NULL);
#endif

	mutex_unlock(&cpu_lock);

	dtrace_hash_destroy(dtrace_bymod);
	dtrace_hash_destroy(dtrace_byfunc);
	dtrace_hash_destroy(dtrace_byname);
	dtrace_bymod = NULL;
	dtrace_byfunc = NULL;
	dtrace_byname = NULL;

	/*
	 * If DTrace helper tracing is enabled, we need to free the trace
	 * buffer.
	 */
	if (dtrace_helptrace_enabled || dtrace_helptrace_buffer)
		vfree(dtrace_helptrace_buffer);

	kmem_cache_destroy(dtrace_state_cachep);

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);

	misc_deregister(&helper_dev);
	misc_deregister(&dtrace_dev);
}
