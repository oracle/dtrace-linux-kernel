/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_hash.c
 * DESCRIPTION:	DTrace - hash table implementation
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

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dtrace.h"

#define DTRACE_HASHSTR(hash, probe)	\
	dtrace_hash_str(*((char **)((uintptr_t)(probe) + (hash)->dth_stroffs)))
#define DTRACE_HASHEQ(hash, lhs, rhs)	\
	(strcmp(*((char **)((uintptr_t)(lhs) + (hash)->dth_stroffs)), \
		*((char **)((uintptr_t)(rhs) + (hash)->dth_stroffs))) == 0)

static uint_t dtrace_hash_str(char *p)
{
	uint_t	g;
	uint_t	hval = 0;

	while (*p) {
		hval = (hval << 4) + *p++;
		g = hval & 0xf0000000;
		if (g != 0)
			hval ^= g >> 24;

		hval &= ~g;
	}

	return hval;
}

struct dtrace_hash *dtrace_hash_create(uintptr_t stroffs, uintptr_t nextoffs,
                                       uintptr_t prevoffs)
{
	struct dtrace_hash *hash;

	hash = kzalloc(sizeof(struct dtrace_hash), GFP_KERNEL);
	if (hash == NULL)
		return NULL;

	hash->dth_stroffs = stroffs;
	hash->dth_nextoffs = nextoffs;
	hash->dth_prevoffs = prevoffs;

	hash->dth_size = 1;
	hash->dth_mask = hash->dth_size - 1;

	hash->dth_tab = vzalloc(hash->dth_size *
				sizeof(struct dtrace_hashbucket *));

	if (hash->dth_tab == NULL) {
		kfree(hash);
		return NULL;
	}

	return hash;
}

void dtrace_hash_destroy(struct dtrace_hash *hash)
{
#ifdef DEBUG
	int	i;

	for (i = 0; i < hash->dth_size; i++)
		ASSERT(hash->dth_tab[i] == NULL);
#endif

	if (hash == NULL)
		return;

	vfree(hash->dth_tab);
	kfree(hash);
}

static int dtrace_hash_resize(struct dtrace_hash *hash)
{
	int			size = hash->dth_size, i, ndx;
	int			new_size = hash->dth_size << 1;
	int			new_mask = new_size - 1;
	struct dtrace_hashbucket **new_tab, *bucket, *next;

	ASSERT((new_size & new_mask) == 0);

	new_tab = vzalloc(new_size * sizeof(void *));
	if (new_tab == NULL)
		return -ENOMEM;

	for (i = 0; i < size; i++) {
		for (bucket = hash->dth_tab[i]; bucket != NULL;
		     bucket = next) {
			struct dtrace_probe *probe = bucket->dthb_chain;

			ASSERT(probe != NULL);
			ndx = DTRACE_HASHSTR(hash, probe) & new_mask;

			next = bucket->dthb_next;
			bucket->dthb_next = new_tab[ndx];
			new_tab[ndx] = bucket;
		}
	}

	vfree(hash->dth_tab);
	hash->dth_tab = new_tab;
	hash->dth_size = new_size;
	hash->dth_mask = new_mask;

	return 0;
}

int dtrace_hash_add(struct dtrace_hash *hash, struct dtrace_probe *new)
{
	int 			hashval = DTRACE_HASHSTR(hash, new);
	int			ndx = hashval & hash->dth_mask;
	struct dtrace_hashbucket *bucket = hash->dth_tab[ndx];
	struct dtrace_probe	**nextp, **prevp;

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, new))
			goto add;
	}

	if ((hash->dth_nbuckets >> 1) > hash->dth_size) {
		int	err = 0;

		err = dtrace_hash_resize(hash);
		if (err != 0)
			return err;

		dtrace_hash_add(hash, new);
		return 0;
	}

	bucket = kzalloc(sizeof(struct dtrace_hashbucket), GFP_KERNEL);
	if (bucket == NULL)
		return -ENOMEM;

	bucket->dthb_next = hash->dth_tab[ndx];
	hash->dth_tab[ndx] = bucket;
	hash->dth_nbuckets++;

add:
	nextp = DTRACE_HASHNEXT(hash, new);

	ASSERT(*nextp == NULL && *(DTRACE_HASHPREV(hash, new)) == NULL);

	*nextp = bucket->dthb_chain;

	if (bucket->dthb_chain != NULL) {
		prevp = DTRACE_HASHPREV(hash, bucket->dthb_chain);

		ASSERT(*prevp == NULL);

		*prevp = new;
	}

	bucket->dthb_chain = new;
	bucket->dthb_len++;

	return 0;
}

struct dtrace_probe *dtrace_hash_lookup(struct dtrace_hash *hash,
                                        struct dtrace_probe *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;

	struct dtrace_hashbucket *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return bucket->dthb_chain;
	}

	return NULL;
}

/*
 * FIXME:
 * It would be more accurate to calculate a lookup cost based on the number
 * of buckets in the hash table slot, the length of the chain, and the length
 * of the string being looked up.
 * The hash tables can also be optimized by storing the hashval in each element
 * rather than always performing string comparisons.
 */
int dtrace_hash_collisions(struct dtrace_hash *hash,
			   struct dtrace_probe *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;

	struct dtrace_hashbucket *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return bucket->dthb_len;
	}

	return 0;
}

void dtrace_hash_remove(struct dtrace_hash *hash, struct dtrace_probe *probe)
{
	int ndx = DTRACE_HASHSTR(hash, probe) & hash->dth_mask;

	struct dtrace_hashbucket *bucket = hash->dth_tab[ndx];
	struct dtrace_probe	**prevp = DTRACE_HASHPREV(hash, probe);
	struct dtrace_probe	**nextp = DTRACE_HASHNEXT(hash, probe);

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, probe))
			break;
	}

	ASSERT(bucket != NULL);

	if (*prevp == NULL) {
		if (*nextp == NULL) {
			/*
			 * This is the last probe in the bucket; we can remove
			 * the bucket.
			 */
			struct dtrace_hashbucket *b = hash->dth_tab[ndx];

			ASSERT(bucket->dthb_chain == probe);
			ASSERT(b != NULL);

			if (b == bucket)
				hash->dth_tab[ndx] = bucket->dthb_next;
			else {
				while (b->dthb_next != bucket)
					b = b->dthb_next;

				b->dthb_next = bucket->dthb_next;
			}

			ASSERT(hash->dth_nbuckets > 0);

			hash->dth_nbuckets--;
			kfree(bucket);

			return;
		}

		bucket->dthb_chain = *nextp;
	} else
		*(DTRACE_HASHNEXT(hash, *prevp)) = *nextp;

	if (*nextp != NULL)
		*(DTRACE_HASHPREV(hash, *nextp)) = *prevp;
}
