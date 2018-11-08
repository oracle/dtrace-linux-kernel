/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Dynamic Tracing for Linux - ARM64 specific assembly
 *
 * Copyright (c) 2017 Oracle and/or its affiliates. All rights reserved.
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

#include <linux/linkage.h>

SYM_CODE_START(dtrace_caller)
	mov	x0, #-1
	ret
SYM_CODE_END(dtrace_caller)

SYM_CODE_START(dtrace_copy)
	ret
SYM_CODE_END(dtrace_copy)

SYM_CODE_START(dtrace_copystr)
	ret
SYM_CODE_END(dtrace_copystr)

SYM_CODE_START(dtrace_fuword8_nocheck)
	ldrb	w0, [x0]
	ret
SYM_CODE_END(dtrace_fuword8_nocheck)

SYM_CODE_START(dtrace_fuword16_nocheck)
	ldrh	w0, [x0]
	ret
SYM_CODE_END(dtrace_fuword16_nocheck)

SYM_CODE_START(dtrace_fuword32_nocheck)
	ldr	w0, [x0]
	ret
SYM_CODE_END(dtrace_fuword32_nocheck)

SYM_CODE_START(dtrace_fuword64_nocheck)
	ldr	x0, [x0]
	ret
SYM_CODE_END(dtrace_fuword64_nocheck)
