/* SPDX-License-Identifier: UPL-1.0 */
/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_FASTRRAP_IOCTL_H_
#define _LINUX_DTRACE_FASTTRAP_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/dtrace/fasttrap.h>

#define FASTTRAPIOC		0xf4
#define FASTTRAPIOC_MAKEPROBE	_IOW(FASTTRAPIOC, 1, struct fasttrap_probe_spec)
#define FASTTRAPIOC_GETINSTR	_IOR(FASTTRAPIOC, 2, struct fasttrap_instr_query)

#endif /* _LINUX_DTRACE_FASTTRAP_IOCTL_H_ */
