/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _CYCLIC_H_
#define _CYCLIC_H_

#include <linux/ktime.h>
#include <linux/types.h>

#define CY_LOW_LEVEL	0
#define CY_LOCK_LEVEL	1
#define CY_HIGH_LEVEL	2
#define CY_SOFT_LEVELS	2
#define CY_LEVELS	3

typedef uintptr_t	cyclic_id_t;
typedef uint16_t	cyc_level_t;
typedef void		(*cyc_func_t)(uintptr_t);

#define CYCLIC_NONE	((cyclic_id_t)0)

struct cyc_handler {
	cyc_func_t cyh_func;
	uintptr_t cyh_arg;
	cyc_level_t cyh_level;
};

#define CY_INTERVAL_INF (-1)

struct cyc_time {
	ktime_t cyt_when;
	ktime_t cyt_interval;
};

struct cyc_omni_handler {
	void (*cyo_online)(void *, uint32_t, struct cyc_handler *,
			   struct cyc_time *);
	void (*cyo_offline)(void *, uint32_t, void *);
	void *cyo_arg;
};

extern cyclic_id_t cyclic_add(struct cyc_handler *, struct cyc_time *);
extern cyclic_id_t cyclic_add_omni(struct cyc_omni_handler *);
extern void cyclic_remove(cyclic_id_t);
extern void cyclic_reprogram(cyclic_id_t, ktime_t);

#endif /* _CYCLIC_H_ */
