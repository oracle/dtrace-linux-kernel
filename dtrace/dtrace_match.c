/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	dtrace_match.c
 * DESCRIPTION:	DTrace - probe match implementation
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

#include "dtrace.h"

struct dtrace_hash	*dtrace_bymod;
struct dtrace_hash	*dtrace_byfunc;
struct dtrace_hash	*dtrace_byname;

int dtrace_match_priv(const struct dtrace_probe *prp, uint32_t priv,
		      kuid_t uid)
{
	if (priv != DTRACE_PRIV_ALL) {
		uint32_t	ppriv =
				prp->dtpr_provider->dtpv_priv.dtpp_flags;
		uint32_t	match = priv & ppriv;

		if ((priv & (DTRACE_PRIV_PROC | DTRACE_PRIV_USER |
		    DTRACE_PRIV_KERNEL)) == 0)
			return 0;

		if (match == 0 && ppriv != 0)
			return 0;

		if (((ppriv & ~match) & DTRACE_PRIV_OWNER) != 0 &&
		    !uid_eq(uid, make_kuid(init_user_namespace,
			       prp->dtpr_provider->dtpv_priv.dtpp_uid)))
			return 0;
	}

	return 1;
}

int dtrace_match_probe(const struct dtrace_probe *prp,
		       const struct dtrace_probekey *pkp,
		       uint32_t priv, kuid_t uid)
{
	struct dtrace_provider	*pvp = prp->dtpr_provider;
	int			rv;

	if (pvp->dtpv_defunct)
		return 0;

	rv = pkp->dtpk_pmatch(pvp->dtpv_name, pkp->dtpk_prov, 0);
	if (rv <= 0)
		return rv;

	rv = pkp->dtpk_mmatch(prp->dtpr_mod, pkp->dtpk_mod, 0);
	if (rv <= 0)
		return rv;

	rv = pkp->dtpk_fmatch(prp->dtpr_func, pkp->dtpk_func, 0);
	if (rv <= 0)
		return rv;

	rv = pkp->dtpk_nmatch(prp->dtpr_name, pkp->dtpk_name, 0);
	if (rv <= 0)
		return rv;

	if (dtrace_match_priv(prp, priv, uid) == 0)
		return 0;

	return rv;
}

int dtrace_match_glob(const char *s, const char *p, int depth)
{
	const char	*olds;
	char		s1, c;
	int		gs;

	if (depth > DTRACE_PROBEKEY_MAXDEPTH)
		return -1;

	if (s == NULL)
		s = "";

top:
	olds = s;
	s1 = *s++;

	if (p == NULL)
		return 0;

	c = *p++;
	if (c == '\0')
		return s1 == '\0';

	switch (c) {
	case '[':
		{
			int	ok = 0, notflag = 0;
			char	lc = '\0';

			if (s1 == '\0')
				return 0;

			if (*p == '!') {
				notflag = 1;
				p++;
			}

			c = *p++;
			if (c == '\0')
				return 0;

			do {
				if (c == '-' && lc != '\0' && *p != ']') {
					c = *p++;
					if (c == '\0')
						return 0;
					if (c == '\\') {
						c = *p++;
						if (c == '\0')
							return 0;
					}
					if (notflag) {
						if (s1 < lc || s1 > c)
							ok++;
						else
							return 0;
					} else if (lc <= s1 && s1 <= c)
						ok++;
				} else if (c == '\\') {
					c = *p++;
					if (c == '\0')
						return 0;
				}
				lc = c;

				if (notflag) {
					if (s1 != c)
						ok++;
					else
						return 0;
				} else if (s1 == c)
					ok++;

				c = *p++;
				if (c == '\0')
					return 0;
			} while (c != ']');

			if (ok)
				goto top;

			return 0;
		}

	case '\\':
		c = *p++;
		if (c == '\0')
			return 0;
		/* fallthru */
	default:
		if (c != s1)
			return 0;
		/* fallthru */

	case '?':
		if (s1 != '\0')
			goto top;

		return 0;

	case '*':
		while (*p == '*')
			p++;

		if (*p == '\0')
			return 1;

		for (s = olds; *s != '\0'; s++) {
			gs = dtrace_match_glob(s, p, depth + 1);
			if (gs != 0)
				return gs;
		}

		return 0;
	}
}

int dtrace_match_string(const char *s, const char *p, int depth)
{
	return s != NULL && strcmp(s, p) == 0;
}

int dtrace_match_nul(const char *s, const char *p, int depth)
{
	return 1;
}

int dtrace_match_nonzero(const char *s, const char *p, int depth)
{
	return s != NULL && s[0] != '\0';
}

struct probe_match {
	const struct dtrace_probekey *pkp;
	uint32_t		priv;
	kuid_t			uid;
	int			(*matched)(struct dtrace_probe *, void *);
	void			*arg;
	int			nmatched;
};

static int dtrace_match_one(int id, void *p, void *data)
{
	struct probe_match	*pbm	= (struct probe_match *)data;
	struct dtrace_probe	*probe	= (struct dtrace_probe *)p;
	int			rc;

	if (dtrace_match_probe(probe, pbm->pkp, pbm->priv, pbm->uid) <= 0)
		return 0;

	pbm->nmatched++;

	rc = (pbm->matched)(probe, pbm->arg);
	if (rc != DTRACE_MATCH_NEXT) {
		if (rc == DTRACE_MATCH_FAIL)
			return DTRACE_MATCH_FAIL;
	}

	return 0;
}

int dtrace_match(const struct dtrace_probekey *pkp, uint32_t priv, kuid_t uid,
		 int (*matched)(struct dtrace_probe *, void *), void *arg)
{
	struct dtrace_probe	template, *probe;
	struct dtrace_hash	*hash = NULL;
	int			len, rc, best = INT_MAX, nmatched = 0;

	if (pkp->dtpk_id != DTRACE_IDNONE) {
		probe = dtrace_probe_lookup_id(pkp->dtpk_id);
		if (probe != NULL &&
		    dtrace_match_probe(probe, pkp, priv, uid) > 0) {
			if ((*matched)(probe, arg) == DTRACE_MATCH_FAIL)
				return DTRACE_MATCH_FAIL;

			nmatched++;
		}

		return nmatched;
	}

	template.dtpr_mod = (char *)pkp->dtpk_mod;
	template.dtpr_func = (char *)pkp->dtpk_func;
	template.dtpr_name = (char *)pkp->dtpk_name;

	if (pkp->dtpk_mmatch == &dtrace_match_string) {
		len = dtrace_hash_collisions(dtrace_bymod, &template);
		if (len < best) {
			best = len;
			hash = dtrace_bymod;
		}
	}

	if (pkp->dtpk_fmatch == &dtrace_match_string) {
		len = dtrace_hash_collisions(dtrace_byfunc, &template);
		if (len < best) {
			best = len;
			hash = dtrace_byfunc;
		}
	}

	if (pkp->dtpk_nmatch == &dtrace_match_string) {
		len = dtrace_hash_collisions(dtrace_byname, &template);
		if (len < best) {
			best = len;
			hash = dtrace_byname;
		}
	}

	if (hash == NULL) {
		struct probe_match	pbm;

		pbm.pkp = pkp;
		pbm.priv = priv;
		pbm.uid = uid;
		pbm.matched = matched;
		pbm.arg = arg;
		pbm.nmatched = 0;

		rc = dtrace_probe_for_each(dtrace_match_one, &pbm);
		if (rc == DTRACE_MATCH_FAIL)
			return DTRACE_MATCH_FAIL;

		return pbm.nmatched;
	}

	for (probe = dtrace_hash_lookup(hash, &template); probe != NULL;
	     probe = *(DTRACE_HASHNEXT(hash, probe))) {
		if (dtrace_match_probe(probe, pkp, priv, uid) <= 0)
			continue;

		nmatched++;

		rc = (*matched)(probe, arg);
		if (rc != DTRACE_MATCH_NEXT) {
			if (rc == DTRACE_MATCH_FAIL)
				return DTRACE_MATCH_FAIL;

			break;
		}
	}

	return nmatched;
}

static dtrace_probekey_f *dtrace_probekey_func(const char *p)
{
	char	c;

	if (p == NULL || *p == '\0')
		return &dtrace_match_nul;

	while ((c = *p++) != '\0') {
		if (c == '[' || c == '?' || c == '*' || c == '\\')
			return &dtrace_match_glob;
	}

	return &dtrace_match_string;
}

void dtrace_probekey(const struct dtrace_probedesc *pdp,
		     struct dtrace_probekey *pkp)
{
	pkp->dtpk_prov = pdp->dtpd_provider;
	pkp->dtpk_pmatch = dtrace_probekey_func(pdp->dtpd_provider);

	pkp->dtpk_mod = pdp->dtpd_mod;
	pkp->dtpk_mmatch = dtrace_probekey_func(pdp->dtpd_mod);

	pkp->dtpk_func = pdp->dtpd_func;
	pkp->dtpk_fmatch = dtrace_probekey_func(pdp->dtpd_func);

	pkp->dtpk_name = pdp->dtpd_name;
	pkp->dtpk_nmatch = dtrace_probekey_func(pdp->dtpd_name);

	pkp->dtpk_id = pdp->dtpd_id;

	if (pkp->dtpk_id == DTRACE_IDNONE &&
	    pkp->dtpk_pmatch == &dtrace_match_nul &&
	    pkp->dtpk_mmatch == &dtrace_match_nul &&
	    pkp->dtpk_fmatch == &dtrace_match_nul &&
	    pkp->dtpk_nmatch == &dtrace_match_nul)
		pkp->dtpk_fmatch = &dtrace_match_nonzero;
}
