/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:        dtrace_sdt_core.c
 * DESCRIPTION: DTrace - SDT probes
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

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_sdt.h>
#include <linux/jhash.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>

const char		*sdt_prefix = "__dtrace_probe_";
int			dtrace_nosdt;

/*
 * Compiled-in SDT probe data.
 */
extern const unsigned long	dtrace_sdt_probes[];
extern const char		dtrace_sdt_strings[];
extern const unsigned long	dtrace_sdt_nprobes;

/*
 * Markers of core-kernel sdt_args and sdt_names sections.
 */
extern const char __start_dtrace_sdt_args[];
extern const char __stop_dtrace_sdt_args[];
extern const char __start_dtrace_sdt_names[];
extern const char __stop_dtrace_sdt_names[];

static int sdt_probe_set(struct sdt_probedesc *sdp, const char *name,
			 const char *func, uintptr_t addr, asm_instr_t **paddr,
			 struct sdt_probedesc *prv)
{
	sdp->sdpd_name = kstrdup(name, GFP_KERNEL);
	if (sdp->sdpd_name == NULL) {
		kfree(sdp);
		return 1;
	}

	sdp->sdpd_func = kstrdup(func, GFP_KERNEL);
	if (sdp->sdpd_func == NULL) {
		kfree(sdp->sdpd_name);
		kfree(sdp);
		return 1;
	}

	sdp->sdpd_args = NULL;
	sdp->sdpd_offset = addr;
	sdp->sdpd_next = NULL;

	*paddr = (asm_instr_t *)addr;

	if (prv && strcmp(prv->sdpd_name, sdp->sdpd_name) == 0
		&& strcmp(prv->sdpd_func, sdp->sdpd_func) == 0)
		prv->sdpd_next = sdp;

	return 0;
}

/*
 * Transfer the SDT args section into the sdpd_args field left NULL above.
 *
 * The memory pointed to by args_start must have a lifetime at least as long as
 * that pointed to by sdpd.
 */
void dtrace_sdt_stash_args(const char *module_name,
			   struct sdt_probedesc *sdpd, size_t nprobes,
			   const char *names_start, size_t names_len,
			   const char *args_start, size_t args_len)
{
	struct probe_name_hashent_t {
		const char *pnhe_name;
		const char *pnhe_args;
	} *args_by_name;
	int i;
	const char *namep, *argp;
	size_t hashsize;

	/*
	 * We need to find the probes (and there may be many) in the sdpd
	 * corresponding to the probe with that name in the argtype section.
	 *
	 * Build a hashtable mapping from probe name -> args string, ignoring
	 * duplicate probe names except to check (in debugging mode) that they
	 * have the same args string as the first.  Then cycle over the sdpd
	 * looking up each probe in turn and pointing to the same place.
	 *
	 * We don't know how many entries there are in the table, but we do know
	 * there cannot be more than nprobes (and are probably less).
	 */

	hashsize = nprobes * 4;			/* arbitrary expansion factor */
	args_by_name = vzalloc(hashsize * sizeof(struct probe_name_hashent_t));
	if (args_by_name == NULL) {
		pr_warn("%s: cannot allocate hash for sdt args population\n",
			__func__);
		return;
	}

	namep = names_start;
	argp = args_start;
	while ((namep < names_start + names_len) &&
	       (argp < args_start + args_len)) {

		size_t l = strlen(namep);
		u32 h = jhash(namep, l, 0) % hashsize;

		while (args_by_name[h].pnhe_name != NULL &&
		       strcmp(args_by_name[h].pnhe_name, namep) != 0) {
			h++;
			h %= hashsize;
		}

		if (args_by_name[h].pnhe_name == NULL) {
			args_by_name[h].pnhe_name = namep;
			args_by_name[h].pnhe_args = argp;
		}
#if defined(CONFIG_DT_DEBUG)
		else if (strcmp(args_by_name[h].pnhe_name, namep) != 0)
			pr_warn("%s: multiple distinct arg strings for probe "
				"%s found: %s versus %s",
				module_name, namep,
				args_by_name[h].pnhe_args,
				argp);
#endif
		namep += l + 1;
		argp += strlen(argp) + 1;
	}

#if defined(CONFIG_DT_DEBUG)
	if ((namep < names_start + names_len) || (argp < args_start + args_len))
		pr_warn("%s: Not all SDT names or args consumed: %zi "
		       "bytes of names and %zi of args left over. "
			"Some arg types will be mis-assigned.\n", module_name,
		       namep - (names_start + names_len),
		       argp - (args_start + args_len));
#endif

	for (i = 0; i < nprobes; i++) {
		size_t l = strlen(sdpd[i].sdpd_name);
		u32 h = jhash(sdpd[i].sdpd_name, l, 0) % hashsize;

		/*
		 * Is-enabled probes have no arg string.
		 */
		if (sdpd[i].sdpd_name[0] == '?')
			continue;

		while (args_by_name[h].pnhe_name != NULL &&
		       strcmp(sdpd[i].sdpd_name,
			      args_by_name[h].pnhe_name) != 0) {
			h++;
			h %= hashsize;
		}

		if (args_by_name[h].pnhe_name == NULL) {
			/*
			 * No arg string. Peculiar: report in debugging mode.
			 */
#if defined(CONFIG_DT_DEBUG)
			pr_warn("%s: probe %s has no arg string.\n",
				module_name, sdpd[i].sdpd_name);
#endif
			continue;
		}

		sdpd[i].sdpd_args = args_by_name[h].pnhe_args;
	}
	vfree(args_by_name);
}

/*
 * Register the SDT probes for the core kernel, i.e. SDT probes that reside in
 * vmlinux.  For SDT probes in kernel modules, we use dtrace_mod_notifier().
 */
void __init dtrace_sdt_register(struct module *mp)
{
	int			i, cnt;
	struct sdt_probedesc	*sdps;
	asm_instr_t		**addrs;
	int			*is_enabled;
	void			*args;
	size_t			args_len;

	if (mp == NULL) {
		pr_warn("%s: no module provided - nothing registered\n",
			__func__);
		return;
	}

	/*
	 * Just in case we run into failures further on...
	 */
	mp->sdt_probes = NULL;
	mp->sdt_probec = 0;

	if (dtrace_sdt_nprobes == 0 || dtrace_nosdt)
		return;

	/*
	 * Allocate the array of SDT probe descriptions to be registered in the
	 * vmlinux pseudo-module.
	 */
	sdps = (struct sdt_probedesc *)vmalloc(dtrace_sdt_nprobes *
					  sizeof(struct sdt_probedesc));
	if (sdps == NULL) {
		pr_warn("%s: cannot allocate SDT probe array\n", __func__);
		return;
	}

	/*
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence), and another
	 * array indicating whether each probe needs patching with an
	 * arch-dependent false return instead.
	 */
	addrs = (asm_instr_t **)vmalloc(dtrace_sdt_nprobes *
					sizeof(asm_instr_t *));
	is_enabled = (int *)vmalloc(dtrace_sdt_nprobes * sizeof(int));
	if ((addrs == NULL) || (is_enabled == NULL)) {
		pr_warn("%s: cannot allocate SDT probe address/is-enabled "
			"lists\n", __func__);
		vfree(sdps);
		vfree(addrs);
		vfree(is_enabled);
		return;
	}

	for (i = cnt = 0; i < dtrace_sdt_nprobes; i++) {
		uintptr_t	addr, poff, foff;
		const char	*fname = &dtrace_sdt_strings[foff];
		const char	*pname;

		addr = dtrace_sdt_probes[i * 3];	/* address */
		poff = dtrace_sdt_probes[i * 3 + 1];	/* probe name offset */
		foff = dtrace_sdt_probes[i * 3 + 2];	/* func name offset */
		pname = &dtrace_sdt_strings[poff];
		fname = &dtrace_sdt_strings[foff];

		is_enabled[cnt] = (pname[0] == '?');

		if (sdt_probe_set(&sdps[cnt], pname, fname, addr, &addrs[cnt],
				  cnt > 0 ? &sdps[cnt - 1] : NULL))
			pr_warn("%s: failed to add SDT probe %s for %s\n",
				__func__, pname, fname);
		else
			cnt++;
	}

	mp->sdt_probes = sdps;
	mp->sdt_probec = cnt;

	dtrace_sdt_nop_multi(addrs, is_enabled, cnt);

	/*
	 * Allocate space for the array of arg types, and copy it in from the
	 * (discardable) kernel section.  We will need to keep it.  (The
	 * identically-ordered array of probe names is not needed after
	 * initialization.)
	 */
	args_len = __stop_dtrace_sdt_args - __start_dtrace_sdt_args;
	args = vmalloc(args_len);
	if (args == NULL) {
		pr_warn("%s: cannot allocate table of SDT arg types\n",
			__func__);
		goto end;
	}

	memcpy(args, __start_dtrace_sdt_args, args_len);

	dtrace_sdt_stash_args("vmlinux", sdps, cnt,
			      __start_dtrace_sdt_names,
			      (__stop_dtrace_sdt_names - __start_dtrace_sdt_names),
			      args, args_len);

end:
	vfree(addrs);
	vfree(is_enabled);
}

static int __init nosdt(char *str)
{
	dtrace_nosdt = 1;

	return 0;
}

early_param("nosdt", nosdt);

void dtrace_sdt_register_module(struct module *mp,
				void *sdt_names_addr, size_t sdt_names_len,
				void *sdt_args_addr, size_t sdt_args_len)
{
	int			i, cnt;
	struct sdt_probedesc	*sdp;
	asm_instr_t		**addrs;
	int			*is_enabled;

	if (mp->sdt_probec == 0 || mp->sdt_probes == NULL)
		return;

	/*
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence).
	 */
	addrs = (asm_instr_t **)vmalloc(mp->sdt_probec *
					sizeof(asm_instr_t *));
	is_enabled = (int *)vmalloc(mp->sdt_probec * sizeof(int));
	if ((addrs == NULL) || (is_enabled == NULL)) {
		pr_warn("%s: cannot allocate SDT probe address list (%s)\n",
			__func__, mp->name);
		vfree(addrs);
		vfree(is_enabled);
		return;
	}

	for (i = cnt = 0, sdp = mp->sdt_probes; i < mp->sdt_probec;
	     i++, sdp++) {
		addrs[cnt] = (asm_instr_t *)sdp->sdpd_offset;
		is_enabled[cnt++] = (sdp->sdpd_name[0] == '?');
	}

	dtrace_sdt_nop_multi(addrs, is_enabled, cnt);

	dtrace_sdt_stash_args(mp->name, mp->sdt_probes, mp->sdt_probec,
			      sdt_names_addr, sdt_names_len,
			      sdt_args_addr, sdt_args_len);

	vfree(addrs);
	vfree(is_enabled);
}

void __init dtrace_sdt_init(void)
{
	dtrace_sdt_init_arch();
}

#if IS_ENABLED(CONFIG_DT_DT_PERF)
void dtrace_sdt_perf(void)
{
	DTRACE_PROBE(measure);
}
EXPORT_SYMBOL(dtrace_sdt_perf);
#endif
