/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	sdt_dev.c
 * DESCRIPTION:	DTrace - SDT provider device driver
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

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

#define SDT_PROBETAB_SIZE	0x1000		/* 4k entries -- 16K total */

struct sdt_probe	**sdt_probetab;
int			sdt_probetab_size;
int			sdt_probetab_mask;

/*
 * Return, in newly-allocated space, a version of the passed-in type 'vartype'
 * which has been cleaned up suitably for CTF: leading and trailing spaces (if
 * any) removed, and optionally a trailing argument removed as well.
 *
 * Type strings look like either
 *
 * type (for SDT, as in function prototypes), or
 *
 * type argname (for perf: as in function declarations).
 *
 * Translator components ": (foo, foo)", if any, have been removed by this
 * stage.
 */
static char *cleanup_type(const char *vartype, int arg_strip)
{
	const char *cleaned;
	const char *p;

	cleaned = vartype + strspn(vartype, " \t");
	for (p = cleaned + strlen(cleaned) - 1; p > cleaned && isspace(*p);
	     p--);
	if (arg_strip) {
		for (; p > cleaned && (isalnum(*p) || *p == '_'); p--);
		for (; p > cleaned && isspace(*p); p--);
	}
	p++;

	return kstrndup(cleaned, p - cleaned, GFP_KERNEL);
}

/*
 * Set up the args lists, extracting them from their sdpd entry and parsing them
 * into an sdt_argdesc array for each probe.
 */
static struct sdt_argdesc *
sdt_setup_args(struct sdt_probedesc *sdpd,
	       size_t *sdp_nargdesc)
{
	struct sdt_argdesc *args;
	char *argstr;
	char *p;
	int arg_strip = 0;
	char *next_arg = NULL;
	size_t arg = 0, sarg = 0, i;

	*sdp_nargdesc = 0;

	if ((sdpd->sdpd_args == NULL) || (sdpd->sdpd_args[0] == '\0'))
		return NULL;

	/*
	 * Take a copy of the string so we can mutate it without causing trouble
	 * on module reload.
	 */
	argstr = kstrdup(sdpd->sdpd_args, GFP_KERNEL);
	if (argstr == NULL)
		goto oom;

	/*
	 * Handle the common case of a trailing comma before we allocate space,
	 * and elide it.
	 */
	p = argstr + strlen(argstr) - 1;
	if (p[0] == ',' && p[1] == '\0')
		*p = '\0';

	/*
	 * This works for counting the number of args even though translator
	 * strings can contain commas, because each comma denotes a new probe
	 * argument.  It may overcount in the case of elided arguments
	 * ("foo : ,"): we compensate for that further down, and ignore the tiny
	 * memory leak that results.
	 */
	for (p = argstr; p != NULL; p = strchr(p + 1, ','))
		(*sdp_nargdesc)++;

	args = kzalloc(*sdp_nargdesc * sizeof(struct sdt_argdesc),
		GFP_KERNEL);
	if (args == NULL)
		goto oom_argstr;

	/*
	 * We need to transform each arg (stripping off a terminal argument
	 * name) if this is a perf probe.
	 */
	if (strncmp(sdpd->sdpd_name, "__perf_", strlen("__perf_")) == 0)
		arg_strip = 1;

	next_arg = argstr;
	do {
		char *tok;
		char *xlator = NULL, *p;
		char *native;
		int parens = 0;
		int empty_xlation;

		/*
		 * Find the end of this arg, and figure out if it has any
		 * translators.  Clean up the type of the arg (or native type,
		 * if this is a translated type).
		 */
		tok = next_arg;
		next_arg = NULL;
		p = strpbrk(tok, "():,");
		while (p && !next_arg) {
			switch (*p) {
			case '(':
				parens++;
				break;
			case ')':
				if (parens > 0)
					parens--;
				break;
			case ':':
				*p = '\0';
				xlator = p + 1;
				break;
			case ',':
				if (parens == 0) {
					*p = '\0';
					next_arg = p + 1;
				}
				break;
			}
			p = strpbrk(p + 1, "():,");
		}

		native = cleanup_type(tok, arg_strip);
		if (native == NULL) {
			args[arg].sda_native = args[arg].sda_xlate = NULL;
			goto full_oom;
		}

		/*
		 * Special case: perf's DECLARE_TRACE_NOARGS passes a single arg
		 * 'void'. Spot and skip it.
		 */
		if (!xlator && arg_strip && strcmp(native, "void") == 0) {
			kfree(native);
			(*sdp_nargdesc)--;
			sarg++;
			continue;
		}

		/*
		 * No translator: straight mapping.
		 */
		if (xlator == NULL) {
			ASSERT(arg < *sdp_nargdesc);
			args[arg].sda_mapping = sarg;
			args[arg].sda_native = native;
			args[arg].sda_xlate = NULL;
			arg++;
			sarg++;
			continue;
		}

		/*
		 * If this is a perf probe, warn: translations cannot exist for
		 * these, and have no defined format yet in any case.  We can
		 * struggle on by assuming they look like SDT translations.
		 */
		if (arg_strip)
			pr_warn("Perf probe %s has at least one SDT translation, "
				"which should be impossible.", sdpd->sdpd_name);

		/*
		 * Zero or more translations.  (If there are zero, i.e. a pair
		 * of empty parentheses or a colon with nothing after it, we
		 * have to decrement the nargdesc.)
		 */

		empty_xlation = 1;
		while ((p = strsep(&xlator, "(,)")) != NULL) {
			/*
			 * Skip the empty space before the ( or after the ).
			 */
			if (strspn(p, " \t") == strlen(p))
				continue;

			ASSERT(arg < *sdp_nargdesc);

			empty_xlation = 0;
			args[arg].sda_mapping = sarg;
			args[arg].sda_native = kstrdup(native, GFP_KERNEL);
			args[arg].sda_xlate = cleanup_type(p, 0);
			if ((args[arg].sda_native == NULL) ||
			    (args[arg].sda_xlate == NULL)) {
				pr_warn("Unable to create argdesc list for "
					"probe %s: out of memory\n",
					sdpd->sdpd_name);
				kfree(native);
				goto full_oom;
			}
			arg++;
		}
		if (empty_xlation)
			(*sdp_nargdesc)--;

		kfree(native);
		sarg++;
	} while (next_arg != NULL);

	kfree(argstr);
	return args;

full_oom:
	for (i = 0; i < arg; i++) {
		kfree(args[i].sda_native);
		kfree(args[i].sda_xlate);
	}
	kfree(args);
oom_argstr:
	kfree(argstr);
oom:
	*sdp_nargdesc = 0;
	pr_warn("Unable to create argdesc list for probe %s: "
		"out of memory\n", sdpd->sdpd_name);
	return NULL;
}

void sdt_provide_module(void *arg, struct module *mp)
{
	char			*modname = mp->name;
	struct dtrace_mprovider	*prov;
	struct sdt_probedesc	*sdpd;
	struct sdt_probe	*sdp, *prv;
	int			idx, len;
	int			probes_skipped = 0;

	/* If module setup has failed then do not provide anything. */
	if (PDATA(mp) == NULL)
		return;

	/*
	 * Nothing to do if the module SDT probes were already created.
	 */
	if (PDATA(mp)->sdt_probe_cnt != 0)
		return;

	/*
	 * Nothing to do if there are no SDT probes.
	 */
	if (mp->sdt_probec == 0)
		return;

	/*
	 * Nothing if arch specific module setup fails.
	 */
	if (!sdt_provide_module_arch(NULL, mp))
		return;

	/*
	 * Do not provide any probes unless all SDT providers have been created
	 * for this meta-provider.
	 */
	for (prov = sdt_providers; prov->dtmp_name != NULL; prov++) {
		if (prov->dtmp_id == DTRACE_PROVNONE)
			return;
	}

	for (idx = 0, sdpd = mp->sdt_probes; idx < mp->sdt_probec;
	     idx++, sdpd++) {
		char			*name = sdpd->sdpd_name, *nname;
		int			i, j;
		struct dtrace_mprovider	*prov;
		dtrace_id_t		id;
		enum fasttrap_probe_type ptype;

		if (name[0] == '?') {
			ptype = SDTPT_IS_ENABLED;
			name++;
		} else
			ptype = SDTPT_OFFSETS;

		for (prov = sdt_providers; prov->dtmp_pref != NULL; prov++) {
			char	*prefix = prov->dtmp_pref;
			int	len = strlen(prefix);

			if (strncmp(name, prefix, len) == 0) {
				name += len;
				break;
			}
		}

		nname = kmalloc(len = strlen(name) + 1, GFP_KERNEL);
		if (nname == NULL) {
			probes_skipped++;
			continue;
		}

		for (i = j = 0; name[j] != '\0'; i++) {
			if (name[j] == '_' && name[j + 1] == '_') {
				nname[i] = '-';
				j += 2;
			} else
				nname[i] = name[j++];
		}

		nname[i] = '\0';

		sdp = kzalloc(sizeof(struct sdt_probe), GFP_KERNEL);
		if (sdp == NULL) {
			probes_skipped++;
			continue;
		}

		sdp->sdp_loadcnt = 1; /* FIXME */
		sdp->sdp_module = mp;
		sdp->sdp_name = nname;
		sdp->sdp_namelen = len;
		sdp->sdp_provider = prov;
		sdp->sdp_ptype = ptype;

		sdp->sdp_argdesc = sdt_setup_args(sdpd, &sdp->sdp_nargdesc);

		id = dtrace_probe_lookup(prov->dtmp_id, modname,
					 sdpd->sdpd_func, nname);
		if (id != DTRACE_IDNONE) {
			prv = dtrace_probe_arg(prov->dtmp_id, id);
			ASSERT(prv != NULL);

			sdp->sdp_next = prv->sdp_next;
			sdp->sdp_id = id;
			prv->sdp_next = sdp;
		} else {
			sdp->sdp_id = dtrace_probe_create(prov->dtmp_id,
							  modname,
							  sdpd->sdpd_func,
							  nname, SDT_AFRAMES,
							  sdp);

			/*
			 * If we failed to create the probe just skip it.
			 */
			if (sdp->sdp_id == DTRACE_IDNONE) {
				kfree(sdp);
				probes_skipped++;
				continue;
			}

			PDATA(mp)->sdt_probe_cnt++;
		}

		sdp->sdp_patchpoint = (asm_instr_t *)sdpd->sdpd_offset;

		sdt_provide_probe_arch(sdp, mp, idx);

		sdp->sdp_hashnext = sdt_probetab[
					SDT_ADDR2NDX(sdp->sdp_patchpoint)];
		sdt_probetab[SDT_ADDR2NDX(sdp->sdp_patchpoint)] = sdp;
	}

	if (probes_skipped != 0)
		pr_warn("sdt: Failed to provide %d probes in %s (out of memory)\n",
			probes_skipped, mp->name);
}

int sdt_enable(void *arg, dtrace_id_t id, void *parg)
{
	struct sdt_probe	*sdp = parg;
	struct sdt_probe	*curr;

	/*
	 * Ensure that we have a reference to the module.
	 */
	if (!try_module_get(sdp->sdp_module))
		return -EAGAIN;

	/*
	 * If at least one other enabled probe exists for this module, drop the
	 * reference we took above, because we only need one to prevent the
	 * module from being unloaded.
	 */
	PDATA(sdp->sdp_module)->enabled_cnt++;
	if (PDATA(sdp->sdp_module)->enabled_cnt > 1)
		module_put(sdp->sdp_module);

	for (curr = sdp; curr != NULL; curr = curr->sdp_next)
		sdt_enable_arch(curr, id, arg);

	return 0;
}

void sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	struct sdt_probe	*sdp = parg;
	struct sdt_probe	*curr;

	for (curr = sdp; curr != NULL; curr = curr->sdp_next)
		sdt_disable_arch(curr, id, arg);

	/*
	 * If we are disabling a probe, we know it was enabled, and therefore
	 * we know that we have a reference on the module to prevent it from
	 * being unloaded.  If we disable the last probe on the module, we can
	 * drop the reference.
	 */
	PDATA(sdp->sdp_module)->enabled_cnt--;
	if (PDATA(sdp->sdp_module)->enabled_cnt == 0)
		module_put(sdp->sdp_module);
}

void sdt_getargdesc(void *arg, dtrace_id_t id, void *parg,
		    struct dtrace_argdesc *desc)
{
	struct sdt_probe	*sdp = parg;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	while ((sdp->sdp_ptype == SDTPT_IS_ENABLED) &&
	       (sdp->sdp_next != NULL))
		sdp = sdp->sdp_next;

	if (sdp->sdp_nargdesc <= desc->dtargd_ndx) {
		desc->dtargd_ndx = DTRACE_ARGNONE;
		return;
	}

	if (sdp->sdp_argdesc[desc->dtargd_ndx].sda_native != NULL)
		strlcpy(desc->dtargd_native,
			sdp->sdp_argdesc[desc->dtargd_ndx].sda_native,
			sizeof(desc->dtargd_native));

	if (sdp->sdp_argdesc[desc->dtargd_ndx].sda_xlate != NULL)
		strlcpy(desc->dtargd_xlate,
			sdp->sdp_argdesc[desc->dtargd_ndx].sda_xlate,
			sizeof(desc->dtargd_xlate));

	desc->dtargd_mapping = sdp->sdp_argdesc[desc->dtargd_ndx].sda_mapping;
}

void sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	struct sdt_probe *sdp = parg;

	PDATA(sdp->sdp_module)->sdt_probe_cnt--;

	while (sdp != NULL) {
		struct sdt_probe *old = sdp, *last, *hash;
		int		 ndx;
		size_t		 i;

		ndx = SDT_ADDR2NDX(sdp->sdp_patchpoint);
		last = NULL;
		hash = sdt_probetab[ndx];

		while (hash != sdp) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->sdp_hashnext;
		}

		if (last != NULL)
			last->sdp_hashnext = sdp->sdp_hashnext;
		else
			sdt_probetab[ndx] = sdp->sdp_hashnext;

		for (i = 0; i < sdp->sdp_nargdesc; i++) {
			kfree(sdp->sdp_argdesc[i].sda_native);
			kfree(sdp->sdp_argdesc[i].sda_xlate);
		}
		kfree(sdp->sdp_argdesc);
		kfree(sdp->sdp_name);
		sdp = sdp->sdp_next;
		kfree(old);
	}
}

static int sdt_open(struct inode *inode, struct file *file)
{
	return -EAGAIN;
}

static int sdt_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations sdt_fops = {
	.owner  = THIS_MODULE,
	.open   = sdt_open,
	.release = sdt_close,
};

static struct miscdevice sdt_dev = {
	.minor = DT_DEV_SDT_MINOR,
	.name = "sdt",
	.nodename = "dtrace/provider/sdt",
	.fops = &sdt_fops,
};

int sdt_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&sdt_dev);
	if (ret) {
		pr_err("%s: Can't register misc device %d\n",
		       sdt_dev.name, sdt_dev.minor);
		return ret;
	}

	if (sdt_probetab_size == 0)
		sdt_probetab_size = SDT_PROBETAB_SIZE;

	sdt_probetab_mask = sdt_probetab_size - 1;
	sdt_probetab = vzalloc(sdt_probetab_size * sizeof(struct sdt_probe *));
	if (sdt_probetab == NULL)
		return -ENOMEM;

	sdt_dev_init_arch();

	return ret;
}

void sdt_dev_exit(void)
{
	sdt_dev_exit_arch();

	vfree(sdt_probetab);

	misc_deregister(&sdt_dev);
}
