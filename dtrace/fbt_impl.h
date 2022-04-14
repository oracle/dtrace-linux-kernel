/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Dynamic Tracing for Linux - Function Boundary Tracing provider
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

#ifndef _FBT_H_
#define _FBT_H_

#include <asm/dtrace_arch.h>
#include <dtrace/fbt_arch.h>

#define FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & \
					fbt_probetab_mask)

extern struct fbt_probe		**fbt_probetab;
extern int			fbt_probetab_size;
extern int			fbt_probetab_mask;

extern void fbt_provide_probe_arch(struct fbt_probe *, int, int);
extern void fbt_enable_arch(struct fbt_probe *, dtrace_id_t, void *);
extern void fbt_disable_arch(struct fbt_probe *, dtrace_id_t, void *);
extern int fbt_can_patch_return_arch(asm_instr_t *);

extern int fbt_provide_module_arch(void *, struct module *);
extern void fbt_provide_module(void *, struct module *);
extern void fbt_destroy_module(void *, struct module *);
extern int fbt_enable(void *, dtrace_id_t, void *);
extern void fbt_disable(void *, dtrace_id_t, void *);
extern uint64_t fbt_getarg(void *, dtrace_id_t, void *, int, int);
extern void fbt_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	fbt_id;

extern int fbt_dev_init_arch(void);
extern void fbt_dev_exit_arch(void);

extern int fbt_dev_init(void);
extern void fbt_dev_exit(void);

#endif /* _FBT_H_ */
