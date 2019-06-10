// SPDX-License-Identifier: GPL-2.0
/*
 * This file provides a generic hashtable implementation for probes.
 *
 * The hashtable is created with 4 user-provided functions:
 *	hval(probe)		- calculate a hash value for the given probe
 *	cmp(probe1, probe2)	- compare two probes
 *	add(head, probe)	- add a probe to a list of probes
 *	del(head, probe)	- delete a probe from a list of probes
 *
 * Probes are hashed into a hashtable slot based on the return value of
 * hval(probe).  Each hashtable slot holds a list of buckets, with each
 * bucket storing probes that are equal under the cmp(probe1, probe2)
 * function. Probes are added to the list of probes in a bucket using the
 * add(head, probe) function, and they are deleted using a call to the
 * del(head, probe) function.
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "dtrace_impl.h"

/*
 * Hashtable implementation for probes.
 */
struct dt_hbucket {
	u32			hval;
	struct dt_hbucket	*next;
	struct dt_probe		*head;
	int			nprobes;
};

struct dt_htab {
	struct dt_hbucket	**tab;
	int			size;
	int			mask;
	int			nbuckets;
	dt_hval_fn		hval;		/* calculate hash value */
	dt_cmp_fn		cmp;		/* compare 2 probes */
	dt_add_fn		add;		/* add probe to list */
	dt_del_fn		del;		/* delete probe from list */
};

/*
 * Create a new (empty) hashtable.
 */
struct dt_htab *dt_htab_new(dt_hval_fn hval, dt_cmp_fn cmp, dt_add_fn add,
			    dt_del_fn del)
{
	struct dt_htab	*htab = malloc(sizeof(struct dt_htab));

	if (!htab)
		return NULL;

	htab->size = 1;
	htab->mask = htab->size - 1;
	htab->nbuckets = 0;
	htab->hval = hval;
	htab->cmp = cmp;
	htab->add = add;
	htab->del = del;

	htab->tab = calloc(htab->size, sizeof(struct dt_hbucket *));
	if (!htab->tab) {
		free(htab);
		return NULL;
	}

	return htab;
}

/*
 * Resize the hashtable by doubling the number of slots.
 */
static int resize(struct dt_htab *htab)
{
	int			i;
	int			osize = htab->size;
	int			nsize = osize << 1;
	int			nmask = nsize - 1;
	struct dt_hbucket	**ntab;

	ntab = calloc(nsize, sizeof(struct dt_hbucket *));
	if (!ntab)
		return -ENOMEM;

	for (i = 0; i < osize; i++) {
		struct dt_hbucket	*bucket, *next;

		for (bucket = htab->tab[i]; bucket; bucket = next) {
			int	idx	= bucket->hval & nmask;

			next = bucket->next;
			bucket->next = ntab[idx];
			ntab[idx] = bucket;
		}
	}

	free(htab->tab);
	htab->tab = ntab;
	htab->size = nsize;
	htab->mask = nmask;

	return 0;
}

/*
 * Add a probe to the hashtable.  Resize if necessary, and allocate a new
 * bucket if necessary.
 */
int dt_htab_add(struct dt_htab *htab, struct dt_probe *probe)
{
	u32			hval = htab->hval(probe);
	int			idx;
	struct dt_hbucket	*bucket;

retry:
	idx = hval & htab->mask;
	for (bucket = htab->tab[idx]; bucket; bucket = bucket->next) {
		if (htab->cmp(bucket->head, probe) == 0)
			goto add;
	}

	if ((htab->nbuckets >> 1) > htab->size) {
		int	err;

		err = resize(htab);
		if (err)
			return err;

		goto retry;
	}

	bucket = malloc(sizeof(struct dt_hbucket));
	if (!bucket)
		return -ENOMEM;

	bucket->hval = hval;
	bucket->next = htab->tab[idx];
	bucket->head = NULL;
	bucket->nprobes = 0;
	htab->tab[idx] = bucket;
	htab->nbuckets++;

add:
	bucket->head = htab->add(bucket->head, probe);
	bucket->nprobes++;

	return 0;
}

/*
 * Find a probe in the hashtable.
 */
struct dt_probe *dt_htab_lookup(const struct dt_htab *htab,
				const struct dt_probe *probe)
{
	u32			hval = htab->hval(probe);
	int			idx = hval & htab->mask;
	struct dt_hbucket	*bucket;

	for (bucket = htab->tab[idx]; bucket; bucket = bucket->next) {
		if (htab->cmp(bucket->head, probe) == 0)
			return bucket->head;
	}

	return NULL;
}

/*
 * Remove a probe from the hashtable.  If we are deleting the last probe in a
 * bucket, get rid of the bucket.
 */
int dt_htab_del(struct dt_htab *htab, struct dt_probe *probe)
{
	u32			hval = htab->hval(probe);
	int			idx = hval & htab->mask;
	struct dt_hbucket	*bucket;
	struct dt_probe		*head;

	for (bucket = htab->tab[idx]; bucket; bucket = bucket->next) {
		if (htab->cmp(bucket->head, probe) == 0)
			break;
	}

	if (bucket == NULL)
		return -ENOENT;

	head = htab->del(bucket->head, probe);
	if (!head) {
		struct dt_hbucket	*b = htab->tab[idx];

		if (bucket == b)
			htab->tab[idx] = bucket->next;
		else {
			while (b->next != bucket)
				b = b->next;

			b->next = bucket->next;
		}

		htab->nbuckets--;
		free(bucket);
	} else
		bucket->head = head;

	return 0;
}
