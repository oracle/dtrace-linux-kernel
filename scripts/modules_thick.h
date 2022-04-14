/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple modules_thick reader.
 *
 * (C) 2014, 2021 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_MODULES_THICK_H
#define _LINUX_MODULES_THICK_H

#include <stdio.h>
#include <stddef.h>

/*
 * modules_thick.builtin iteration state.
 */
struct modules_thick_iter {
	FILE *f;
	char *line;
	size_t line_size;
};

/*
 * Construct a modules_thick.builtin iterator.
 */
struct modules_thick_iter *
modules_thick_iter_new(const char *modules_thick_file);

/*
 * Iterate, returning a new null-terminated array of object file names, and a
 * new dynamically-allocated module name.  (The module name passed in is freed.)
 *
 * The array of object file names should be freed by the caller: the strings it
 * points to are owned by the iterator, and should not be freed.
 */

char ** __attribute__((__nonnull__))
modules_thick_iter_next(struct modules_thick_iter *i, char **module_name);

void
modules_thick_iter_free(struct modules_thick_iter *i);

#endif
