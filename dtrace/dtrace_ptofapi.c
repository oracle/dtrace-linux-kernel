/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_ptofapi.c
 * DESCRIPTION:	DTrace - (meta) provider-to-framework API
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

#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "dtrace.h"

struct dtrace_provider	*dtrace_provider;
struct dtrace_meta	*dtrace_meta_pid;
struct dtrace_helpers	*dtrace_deferred_pid;

DEFINE_MUTEX(dtrace_provider_lock);
DEFINE_MUTEX(dtrace_meta_lock);

/*
 * Register the calling provider with the DTrace core.  This should generally
 * be called by providers during module initialization.
 */
int dtrace_register(const char *name, const struct dtrace_pattr *pap,
		    uint32_t priv, const struct cred *cr,
		    const struct dtrace_pops *pops, void *arg,
		    dtrace_provider_id_t *idp)
{
	struct dtrace_provider	*provider;

	if (name == NULL || pap == NULL || pops == NULL || idp == NULL) {
		pr_warn("Failed to register provider %s: invalid args\n",
			name ? name : "<NULL>");
		return -EINVAL;
	}

	if (name[0] == '\0' || dtrace_badname(name)) {
		pr_warn("Failed to register provider %s: invalid name\n",
			name);
		return -EINVAL;
	}

	if ((pops->dtps_provide == NULL && pops->dtps_provide_module == NULL) ||
	    pops->dtps_enable == NULL || pops->dtps_disable == NULL ||
	    pops->dtps_destroy == NULL ||
	    ((pops->dtps_resume == NULL) != (pops->dtps_suspend == NULL))) {
		pr_warn("Failed to register provider %s: invalid ops\n",
			name);
		return -EINVAL;
	}

	if (dtrace_badattr(&pap->dtpa_provider) ||
	    dtrace_badattr(&pap->dtpa_mod) ||
	    dtrace_badattr(&pap->dtpa_func) ||
	    dtrace_badattr(&pap->dtpa_name) ||
	    dtrace_badattr(&pap->dtpa_args)) {
		pr_warn("Failed to register provider %s: invalid attributes\n",
			name);
		return -EINVAL;
	}

	if (priv & ~DTRACE_PRIV_ALL) {
		pr_warn("Failed to register provider %s: invalid privilege "
			"attributes\n", name);
		return -EINVAL;
	}

	if ((priv & DTRACE_PRIV_KERNEL) &&
	    (priv & (DTRACE_PRIV_USER | DTRACE_PRIV_OWNER)) &&
	    pops->dtps_usermode == NULL) {
		pr_warn("Failed to register provider %s: need "
			"dtps_usermode() op for given privilege "
			"attributes\n", name);
		return -EINVAL;
	}

	dt_dbg_prov("Registering provider '%s'...\n", name);
	provider = kzalloc(sizeof(struct dtrace_provider), GFP_KERNEL);
	if (provider == NULL) {
		dt_dbg_prov("  Failed to allocate provider struct\n");
		return -ENOMEM;
	}
	provider->dtpv_name = dtrace_strdup(name);
	if (provider->dtpv_name == NULL) {
		kfree(provider);
		dt_dbg_prov("  Failed to allocate provider name\n");
		return -ENOMEM;
	}
	provider->dtpv_attr = *pap;
	provider->dtpv_priv.dtpp_flags = priv;

	if (cr != NULL) {
		provider->dtpv_priv.dtpp_uid =
			from_kuid(init_user_namespace, get_cred(cr)->uid);
		put_cred(cr);
	}

	provider->dtpv_pops = *pops;

	if (pops->dtps_provide == NULL) {
		ASSERT(pops->dtps_provide_module != NULL);
		provider->dtpv_pops.dtps_provide =
		    (void (*)(void *, const struct dtrace_probedesc *))
			dtrace_nullop;
	}

	if (pops->dtps_provide_module == NULL) {
		ASSERT(pops->dtps_provide != NULL);
		provider->dtpv_pops.dtps_provide_module =
		    (void (*)(void *, struct module *))dtrace_nullop;
	}

	if (pops->dtps_destroy_module == NULL) {
		provider->dtpv_pops.dtps_destroy_module =
		    (void (*)(void *, struct module *))dtrace_nullop;
	}

	if (pops->dtps_suspend == NULL) {
		ASSERT(pops->dtps_resume == NULL);
		provider->dtpv_pops.dtps_suspend =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
		provider->dtpv_pops.dtps_resume =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
	}

	provider->dtpv_arg = arg;
	*idp = (dtrace_provider_id_t)provider;

	if (pops == &dtrace_provider_ops) {
		ASSERT(MUTEX_HELD(&dtrace_provider_lock));
		ASSERT(MUTEX_HELD(&dtrace_lock));
		ASSERT(dtrace_anon.dta_enabling == NULL);

		/*
		 * The DTrace provider must be at the head of the provider
		 * chain.
		 */
		provider->dtpv_next = dtrace_provider;
		dtrace_provider = provider;

		dt_dbg_prov("  Done registering %s\n", name);

		return 0;
	}

	mutex_lock(&module_mutex);
	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * If there is at least one provider registered, we'll add this new one
	 * after the first provider.
	 */
	if (dtrace_provider != NULL) {
		provider->dtpv_next = dtrace_provider->dtpv_next;
		dtrace_provider->dtpv_next = provider;
	} else
		dtrace_provider = provider;

	if (dtrace_retained != NULL) {
		dt_dbg_prov("  Processing retained enablings for %s\n", name);
		dtrace_enabling_provide(provider);

		/*
		 * We must now call dtrace_enabling_matchall() which needs to
		 * acquire cpu_lock and dtrace_lock.  We therefore need to drop
		 * our locks before calling it.
		 */
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_provider_lock);
		mutex_unlock(&module_mutex);
		dtrace_enabling_matchall();

		dt_dbg_prov("  Done registering %s\n", name);

		return 0;
	}

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
	mutex_unlock(&module_mutex);

	dt_dbg_prov("  Done registering %s\n", name);

	return 0;
}
EXPORT_SYMBOL(dtrace_register);

struct unreg_state {
	struct dtrace_provider	*prov;
	struct dtrace_probe	*first;
};

/*
 * Check whether the given probe is still enabled for the given provider.
 */
static int dtrace_unregister_check(int id, void *p, void *data)
{
	struct dtrace_probe	*probe = (struct dtrace_probe *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	if (probe->dtpr_ecb == NULL)
		return 0;

	return -EBUSY;
}

/*
 * Remove the given probe from the hash tables and the probe IDR, if it is
 * associated with the given provider.  The probes are chained for further
 * processing.
 */
static int dtrace_unregister_probe(int id, void *p, void *data)
{
	struct dtrace_probe	*probe = (struct dtrace_probe *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	dtrace_hash_remove(dtrace_bymod, probe);
	dtrace_hash_remove(dtrace_byfunc, probe);
	dtrace_hash_remove(dtrace_byname, probe);

	if (st->first == NULL) {
		st->first = probe;
		probe->dtpr_nextmod = NULL;
	} else {
		probe->dtpr_nextmod = st->first;
		st->first = probe;
	}

	return 0;
}

/*
 * Remove the given probe from the hash tables and the probe IDR, if it is
 * associated with the given provider and if it does not have any enablings.
 * The probes are chained for further processing.
 */
static int dtrace_condense_probe(int id, void *p, void *data)
{
	struct dtrace_probe	*probe = (struct dtrace_probe *)p;
	struct unreg_state	*st = (struct unreg_state *)data;

	if (probe->dtpr_provider != st->prov)
		return 0;

	if (probe->dtpr_ecb == NULL)
		return 0;

	dtrace_hash_remove(dtrace_bymod, probe);
	dtrace_hash_remove(dtrace_byfunc, probe);
	dtrace_hash_remove(dtrace_byname, probe);

	if (st->first == NULL) {
		st->first = probe;
		probe->dtpr_nextmod = NULL;
	} else {
		probe->dtpr_nextmod = st->first;
		st->first = probe;
	}

	return 0;
}

/*
 * Unregister the specified provider from the DTrace core.  This should be
 * called by provider during module cleanup.
 *
 * The mutex_lock is already held during this call.
 */
int dtrace_unregister(dtrace_provider_id_t id)
{
	struct dtrace_provider	*old = (struct dtrace_provider *)id;
	struct dtrace_provider	*prev = NULL;
	int			err, self = 0;
	struct dtrace_probe	*probe;
	struct unreg_state	st = { old, NULL };

	ASSERT(MUTEX_HELD(&module_mutex));

	dt_dbg_prov("Unregistering provider '%s'...\n", old->dtpv_name);

	if (old->dtpv_pops.dtps_enable ==
	    (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop) {
		/*
		 * When the provider is the DTrace core itself, we're called
		 * with locks already held.
		 */
		ASSERT(old == dtrace_provider);
		ASSERT(MUTEX_HELD(&dtrace_provider_lock));
		ASSERT(MUTEX_HELD(&dtrace_lock));

		self = 1;

		if (dtrace_provider->dtpv_next != NULL) {
			/*
			 * We cannot and should not remove the DTrace provider
			 * if there is any other provider left.
			 */
			dt_dbg_prov("  Failed to unregister %s - not last\n",
				    old->dtpv_name);

			return -EBUSY;
		}
	} else {
		mutex_lock(&dtrace_provider_lock);
		mutex_lock(&dtrace_lock);
	}

	/*
	 * If /dev/dtrace/dtrace is still held open by a process, or if there
	 * are anonymous probes that are still enabled, we refuse to deregister
	 * providers, unless the provider has been invalidated explicitly.
	 */
	if (!old->dtpv_defunct &&
	    (dtrace_opens || (dtrace_anon.dta_state != NULL &&
	     dtrace_anon.dta_state->dts_necbs > 0))) {
		if (!self) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&dtrace_provider_lock);
		}

		dt_dbg_prov("  Failed to unregister %s - dtrace in use\n",
			    old->dtpv_name);

		return -EBUSY;
	}

	/*
	 * Check whether any of the probes associated with this provider are
	 * still enabled (having at least one ECB).  If any are found, we
	 * cannot remove this provider.
	 */
	st.prov = old;
	err = dtrace_probe_for_each(dtrace_unregister_check, &st);
	if (err < 0) {
		if (!self) {
			mutex_unlock(&dtrace_lock);
			mutex_unlock(&dtrace_provider_lock);
		}

		dt_dbg_prov("  Failed to unregister %s - provider in use\n",
			    old->dtpv_name);

		return err;
	}

	/*
	 * All the probes associated with this provider are disabled.  We can
	 * safely remove these probes from the hashtables and the probe array.
	 * We chain all the probes together for further processing.
	 */
	dtrace_probe_for_each(dtrace_unregister_probe, &st);

	/*
	 * The probes associated with the provider have been removed.  Ensure
	 * synchronization on probe IDR processing.
	 */
	dtrace_sync();

	/*
	 * Now get rid of the actual probes.
	 */
	for (probe = st.first; probe != NULL; probe = st.first) {
		int	probe_id = probe->dtpr_id;

		st.first = probe->dtpr_nextmod;

		old->dtpv_pops.dtps_destroy(old->dtpv_arg, probe_id,
					    probe->dtpr_arg);

		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
		kmem_cache_free(dtrace_probe_cachep, probe);

		dtrace_probe_remove_id(probe_id);
	}

	prev = dtrace_provider;
	if (prev == old) {
		/*
		 * We are removing the provider at the head of the chain.
		 */
		ASSERT(self);
		ASSERT(old->dtpv_next == NULL);

		dtrace_provider = old->dtpv_next;
	} else {
		while (prev != NULL && prev->dtpv_next != old)
			prev = prev->dtpv_next;

		if (prev == NULL) {
			pr_err("Attempt to unregister non-existent DTrace "
			       "provider %p\n", (void *)id);
			BUG();
		}

		prev->dtpv_next = old->dtpv_next;
	}

	if (!self) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_provider_lock);
	}

	kfree(old->dtpv_name);
	kfree(old);

	dt_dbg_prov("  Done unregistering\n");

	return 0;
}
EXPORT_SYMBOL(dtrace_unregister);

/*
 * Invalidate the specified provider.  All subsequent probe lookups for the
 * specified provider will fail, but the probes will not be removed.
 */
void dtrace_invalidate(dtrace_provider_id_t id)
{
	struct dtrace_provider	*pvp = (struct dtrace_provider *)id;

	ASSERT(pvp->dtpv_pops.dtps_enable !=
	       (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	pvp->dtpv_defunct = 1;

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);
}
EXPORT_SYMBOL(dtrace_invalidate);

/*
 * Indicate whether or not DTrace has attached.
 */
int dtrace_attached(void)
{
	/*
	 * dtrace_provider will be non-NULL iff the DTrace driver has
	 * attached.  (It's non-NULL because DTrace is always itself a
	 * provider.)
	 */
	return dtrace_provider != NULL;
}
EXPORT_SYMBOL(dtrace_attached);

/*
 * Remove all the unenabled probes for the given provider.  This function is
 * not unlike dtrace_unregister(), except that it doesn't remove the provider
 * -- just as many of its associated probes as it can.
 */
int dtrace_condense(dtrace_provider_id_t id)
{
	struct dtrace_provider	*prov = (struct dtrace_provider *)id;
	struct dtrace_probe	*probe;
	struct unreg_state	st = { prov, NULL };

	/*
	 * Make sure this isn't the DTrace provider itself.
	 */
	ASSERT(prov->dtpv_pops.dtps_enable !=
	       (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	mutex_lock(&dtrace_provider_lock);
	mutex_lock(&dtrace_lock);

	/*
	 * Attempt to destroy the probes associated with this provider.
	 */
	dtrace_probe_for_each(dtrace_condense_probe, &st);

	/*
	 * The probes associated with the provider have been removed.  Ensure
	 * synchronization on probe IDR processing.
	 */
	dtrace_sync();

	/*
	 * Now get rid of the actual probes.
	 */
	for (probe = st.first; probe != NULL; probe = st.first) {
		int	probe_id = probe->dtpr_id;

		st.first = probe->dtpr_nextmod;

		prov->dtpv_pops.dtps_destroy(prov->dtpv_arg, probe_id,
					     probe->dtpr_arg);

		kfree(probe->dtpr_mod);
		kfree(probe->dtpr_func);
		kfree(probe->dtpr_name);
		kfree(probe);

		dtrace_probe_remove_id(probe_id);
	}

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_provider_lock);

	return 0;
}
EXPORT_SYMBOL(dtrace_condense);

int dtrace_meta_register(const char *name, const struct dtrace_mops *mops,
			 void *arg, dtrace_meta_provider_id_t *idp)
{
	struct dtrace_meta	*meta;
	struct dtrace_helpers	*help, *next;
	int			i;

	*idp = DTRACE_METAPROVNONE;

	/*
	 * We strictly don't need the name, but we hold onto it for
	 * debuggability. All hail error queues!
	 */
	if (name == NULL) {
		pr_warn("failed to register meta-provider: invalid name\n");
		return -EINVAL;
	}

	if (mops == NULL ||
	    mops->dtms_create_probe == NULL ||
	    mops->dtms_provide_pid == NULL ||
	    mops->dtms_remove_pid == NULL) {
		pr_warn("failed to register meta-register %s: invalid ops\n",
			name);
		return -EINVAL;
	}

	dt_dbg_prov("Registering provider '%s'...\n", name);
	meta = kzalloc(sizeof(struct dtrace_meta), GFP_KERNEL);
	if (meta == NULL) {
		dt_dbg_prov("  Failed to allocate meta provider struct\n");
		return -ENOMEM;
	}
	meta->dtm_mops = *mops;
	meta->dtm_name = kmalloc(strlen(name) + 1, GFP_KERNEL);
	if (meta->dtm_name == NULL) {
		kfree(meta);
		dt_dbg_prov("  Failed to allocate meta provider name\n");
		return -ENOMEM;
	}
	strcpy(meta->dtm_name, name);
	meta->dtm_arg = arg;

	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (dtrace_meta_pid != NULL) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_meta_lock);
		pr_warn("failed to register meta-register %s: user-land "
			"meta-provider exists", name);
		kfree(meta->dtm_name);
		kfree(meta);
		return -EINVAL;
	}

	dtrace_meta_pid = meta;
	*idp = (dtrace_meta_provider_id_t)meta;

	/*
	 * If there are providers and probes ready to go, pass them
	 * off to the new meta provider now.
	 */
	help = dtrace_deferred_pid;
	dtrace_deferred_pid = NULL;

	mutex_unlock(&dtrace_lock);

	while (help != NULL) {
		for (i = 0; i < help->dthps_nprovs; i++) {
			dtrace_helper_provide(&help->dthps_provs[i]->dthp_prov,
					      help->dthps_pid);
		}

		next = help->dthps_next;
		help->dthps_next = NULL;
		help->dthps_prev = NULL;
		help->dthps_deferred = 0;
		help = next;
	}

	mutex_unlock(&dtrace_meta_lock);

	dt_dbg_prov("  Done registering %s\n", name);

	return 0;
}
EXPORT_SYMBOL(dtrace_meta_register);

int dtrace_meta_unregister(dtrace_meta_provider_id_t id)
{
	struct dtrace_meta **pp, *old = (struct dtrace_meta *)id;

	dt_dbg_prov("Unregistering meta provider '%s'...\n", old->dtm_name);
	mutex_lock(&dtrace_meta_lock);
	mutex_lock(&dtrace_lock);

	if (old == dtrace_meta_pid) {
		pp = &dtrace_meta_pid;
	} else {
		pr_err("Attempt to unregister non-existent DTrace meta-"
		       "provider %p\n", (void *)old);
		BUG();
	}

	if (old->dtm_count != 0) {
		mutex_unlock(&dtrace_lock);
		mutex_unlock(&dtrace_meta_lock);
		return -EBUSY;
	}

	*pp = NULL;

	mutex_unlock(&dtrace_lock);
	mutex_unlock(&dtrace_meta_lock);

	kfree(old->dtm_name);
	kfree(old);

	dt_dbg_prov("  Done unregistering\n");

	return 0;
}
EXPORT_SYMBOL(dtrace_meta_unregister);
