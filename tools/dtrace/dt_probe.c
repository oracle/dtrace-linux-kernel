// SPDX-License-Identifier: GPL-2.0
/*
 * This file implements the interface to probes grouped by provider.
 *
 * Probes are named by a set of 4 identifiers:
 *	- provider name
 *	- module name
 *	- function name
 *	- probe name
 *
 * The Fully Qualified Name (FQN) is "provider:module:function:name".
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/kernel.h>

#include "dtrace_impl.h"

static struct dt_provider      *dt_providers[] = {
							&dt_fbt,
							&dt_syscall,
						 };

static struct dt_htab	*ht_byfqn;

static u32		next_probe_id;

/*
 * Calculate a hash value based on a given string and an initial value.  The
 * initial value is used to calculate compound hash values, e.g.
 *
 *	u32	hval;
 *
 *	hval = str2hval(str1, 0);
 *	hval = str2hval(str2, hval);
 */
static u32 str2hval(const char *p, u32 hval)
{
	u32	g;

	if (!p)
		return hval;

	while (*p) {
		hval = (hval << 4) + *p++;
		g = hval & 0xf0000000;
		if (g != 0)
			hval ^= g >> 24;

		hval &= ~g;
	}

	return hval;
}

/*
 * String compare function that can handle either or both strings being NULL.
 */
static int safe_strcmp(const char *p, const char *q)
{
	return (!p) ? (!q) ? 0
			   : -1
		    : (!q) ? 1
			   : strcmp(p, q);
}

/*
 * Calculate the hash value of a probe as the cummulative hash value of the
 * FQN.
 */
static u32 fqn_hval(const struct dt_probe *probe)
{
	u32	hval = 0;

	hval = str2hval(probe->prv_name, hval);
	hval = str2hval(":", hval);
	hval = str2hval(probe->mod_name, hval);
	hval = str2hval(":", hval);
	hval = str2hval(probe->fun_name, hval);
	hval = str2hval(":", hval);
	hval = str2hval(probe->prb_name, hval);

	return hval;
}

/*
 * Compare two probes based on the FQN.
 */
static int fqn_cmp(const struct dt_probe *p, const struct dt_probe *q)
{
	int	rc;

	rc = safe_strcmp(p->prv_name, q->prv_name);
	if (rc)
		return rc;
	rc = safe_strcmp(p->mod_name, q->mod_name);
	if (rc)
		return rc;
	rc = safe_strcmp(p->fun_name, q->fun_name);
	if (rc)
		return rc;
	rc = safe_strcmp(p->prb_name, q->prb_name);
	if (rc)
		return rc;

	return 0;
}

/*
 * Add the given probe 'new' to the double-linked probe list 'head'.  Probe
 * 'new' becomes the new list head.
 */
static struct dt_probe *fqn_add(struct dt_probe *head, struct dt_probe *new)
{
	if (!head)
		return new;

	new->he_fqn.next = head;
	head->he_fqn.prev = new;

	return new;
}

/*
 * Remove the given probe 'probe' from the double-linked probe list 'head'.
 * If we are deleting the current head, the next probe in the list is returned
 * as the new head.  If that value is NULL, the list is now empty.
 */
static struct dt_probe *fqn_del(struct dt_probe *head, struct dt_probe *probe)
{
	if (head == probe) {
		if (!probe->he_fqn.next)
			return NULL;

		head = probe->he_fqn.next;
		head->he_fqn.prev = NULL;
		probe->he_fqn.next = NULL;

		return head;
	}

	if (!probe->he_fqn.next) {
		probe->he_fqn.prev->he_fqn.next = NULL;
		probe->he_fqn.prev = NULL;

		return head;
	}

	probe->he_fqn.prev->he_fqn.next = probe->he_fqn.next;
	probe->he_fqn.next->he_fqn.prev = probe->he_fqn.prev;
	probe->he_fqn.prev = probe->he_fqn.next = NULL;

	return head;
}

/*
 * Initialize the probe handling by populating the FQN hashtable with probes
 * from all providers.
 */
int dt_probe_init(void)
{
	int	i;

	ht_byfqn = dt_htab_new(fqn_hval, fqn_cmp, fqn_add, fqn_del);

	for (i = 0; i < ARRAY_SIZE(dt_providers); i++) {
		if (dt_providers[i]->populate() < 0)
			return -1;
	}

	return 0;
}

/*
 * Allocate a new probe and add it to the FQN hashtable.
 */
int dt_probe_new(const struct dt_provider *prov, const char *pname,
		 const char *mname, const char *fname, const char *name)
{
	struct dt_probe	*probe;

	probe = malloc(sizeof(struct dt_probe));
	if (!probe)
		return -ENOMEM;

	memset(probe, 0, sizeof(struct dt_probe));
	probe->id = next_probe_id++;
	probe->prov = prov;
	probe->prv_name = pname ? strdup(pname) : NULL;
	probe->mod_name = mname ? strdup(mname) : NULL;
	probe->fun_name = fname ? strdup(fname) : NULL;
	probe->prb_name = name ? strdup(name) : NULL;

	dt_htab_add(ht_byfqn, probe);

	return 0;
}

/*
 * Perform a probe lookup based on FQN.
 */
struct dt_probe *dt_probe_by_name(const struct dt_probe *tmpl)
{
	return dt_htab_lookup(ht_byfqn, tmpl);
}

/*
 * Resolve an event name (BPF ELF section name) into a probe.  We query each
 * provider, and as soon as we get a hit, we return the result.
 */
struct dt_probe *dt_probe_resolve_event(const char *name)
{
	int		i;
	struct dt_probe	*probe;

	for (i = 0; i < ARRAY_SIZE(dt_providers); i++) {
		if (!dt_providers[i]->resolve_event)
			continue;
		probe = dt_providers[i]->resolve_event(name);
		if (probe)
			return probe;
	}

	return NULL;
}
