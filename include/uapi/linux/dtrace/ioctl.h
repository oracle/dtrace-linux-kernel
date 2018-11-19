/* SPDX-License-Identifier: UPL-1.0 */
/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_IOCTL_H_
#define _LINUX_DTRACE_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/dtrace/arg.h>
#include <linux/dtrace/buffer.h>
#include <linux/dtrace/conf.h>
#include <linux/dtrace/dof.h>
#include <linux/dtrace/enabling.h>
#include <linux/dtrace/helpers.h>
#include <linux/dtrace/metadesc.h>
#include <linux/dtrace/stability.h>
#include <linux/dtrace/status.h>
#include <linux/dtrace/cpu_defines.h>

#define DTRACEIOC		0xd4
#define DTRACEIOC_PROVIDER	_IOR(DTRACEIOC, 1, struct dtrace_providerdesc)
#define DTRACEIOC_PROBES	_IOR(DTRACEIOC, 2, struct dtrace_probedesc)
#define DTRACEIOC_BUFSNAP	_IOR(DTRACEIOC, 4, struct dtrace_bufdesc)
#define DTRACEIOC_PROBEMATCH	_IOR(DTRACEIOC, 5, struct dtrace_probedesc)
#define DTRACEIOC_ENABLE	_IOW(DTRACEIOC, 6, void *)
#define DTRACEIOC_AGGSNAP	_IOR(DTRACEIOC, 7, struct dtrace_bufdesc)
#define DTRACEIOC_EPROBE	_IOW(DTRACEIOC, 8, struct dtrace_eprobedesc)
#define DTRACEIOC_PROBEARG	_IOR(DTRACEIOC, 9, struct dtrace_argdesc)
#define DTRACEIOC_CONF		_IOR(DTRACEIOC, 10, struct dtrace_conf)
#define DTRACEIOC_STATUS	_IOR(DTRACEIOC, 11, struct dtrace_status)
#define DTRACEIOC_GO		_IOW(DTRACEIOC, 12, processorid_t)
#define DTRACEIOC_STOP		_IOW(DTRACEIOC, 13, processorid_t)
#define DTRACEIOC_AGGDESC	_IOR(DTRACEIOC, 15, struct dtrace_aggdesc)
#define DTRACEIOC_FORMAT	_IOR(DTRACEIOC, 16, struct dtrace_fmtdesc)
#define DTRACEIOC_DOFGET	_IOR(DTRACEIOC, 17, struct dof_hdr)
#define DTRACEIOC_REPLICATE	_IOR(DTRACEIOC, 18, void *)

#define DTRACEHIOC		0xd8
#define DTRACEHIOC_ADD		_IOW(DTRACEHIOC, 1, struct dof_hdr)
#define DTRACEHIOC_REMOVE	_IOW(DTRACEHIOC, 2, int)
#define DTRACEHIOC_ADDDOF	_IOW(DTRACEHIOC, 3, struct dof_helper)

#endif /* _LINUX_DTRACE_IOCTL_H */
