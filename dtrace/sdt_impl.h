/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Dynamic Tracing for Linux - Statically Defined Tracing provider
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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

#ifndef _SDT_IMPL_H_
#define _SDT_IMPL_H_

#include <linux/sdt.h>
#include <asm/dtrace_arch.h>
#include <dtrace/sdt_arch.h>

extern struct module		*dtrace_kmod;

struct sdt_argdesc;

enum fasttrap_probe_type {
	SDTPT_NONE = 0,
	SDTPT_OFFSETS,
	SDTPT_IS_ENABLED
};

struct sdt_probe {
	struct dtrace_mprovider	*sdp_provider;	/* provider */
	char			*sdp_name;	/* name of probe */
	int			sdp_namelen;	/* length of allocated name */
	dtrace_id_t		sdp_id;		/* probe ID */
	struct module		*sdp_module;	/* modctl for module */
	int			sdp_loadcnt;	/* load count for module */
	int			sdp_primary;	/* non-zero if primary mod */
	enum fasttrap_probe_type sdp_ptype;	/* probe type */
	asm_instr_t		*sdp_patchpoint;/* patch point */
	asm_instr_t		sdp_patchval;	/* instruction to patch */
	asm_instr_t		sdp_savedval;	/* saved instruction value */
	struct sdt_argdesc	*sdp_argdesc;	/* arguments for this probe */
	size_t			sdp_nargdesc;	/* number of arguments */
	struct sdt_probe	*sdp_next;	/* next probe */
	struct sdt_probe	*sdp_hashnext;	/* next on hash */
};

struct sdt_argdesc {
	int			sda_mapping;
	char			*sda_native;
	char			*sda_xlate;
};

extern struct dtrace_mprovider	sdt_providers[];
extern struct sdt_probe		**sdt_probetab;
extern int			sdt_probetab_size;
extern int			sdt_probetab_mask;

#define SDT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & \
					sdt_probetab_mask)

extern void sdt_provide_probe_arch(struct sdt_probe *, struct module *, int);
extern int sdt_provide_module_arch(void *, struct module *);
extern void sdt_enable_arch(struct sdt_probe *, dtrace_id_t, void *);
extern void sdt_disable_arch(struct sdt_probe *, dtrace_id_t, void *);

extern void sdt_provide_module(void *, struct module *);
extern void sdt_destroy_module(void *, struct module *);
extern int sdt_enable(void *, dtrace_id_t, void *);
extern void sdt_disable(void *, dtrace_id_t, void *);
extern void sdt_getargdesc(void *, dtrace_id_t, void *,
			   struct dtrace_argdesc *);
extern uint64_t sdt_getarg(void *, dtrace_id_t, void *, int, int);
extern void sdt_destroy(void *, dtrace_id_t, void *);

extern int sdt_dev_init(void);
extern void sdt_dev_exit(void);

extern int sdt_dev_init_arch(void);
extern void sdt_dev_exit_arch(void);

#endif /* _SDT_IMPL_H_ */
