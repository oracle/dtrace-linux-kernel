/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FILE:	sdt_mod.c
 * DESCRIPTION:	DTrace - SDT provider kernel module
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

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Profile Interrupt Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("GPL");

static struct dtrace_pattr vtrace_attr = {
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr info_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr fc_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr fpu_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_CPU },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr fsinfo_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr stab_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr sdt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr xpv_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
};

static struct dtrace_pattr iscsi_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static struct dtrace_pattr perf_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static struct dtrace_pops sdt_pops = {
	.dtps_provide = NULL,
	.dtps_provide_module = sdt_provide_module,
	.dtps_destroy_module = sdt_destroy_module,
	.dtps_enable = sdt_enable,
	.dtps_disable = sdt_disable,
	.dtps_suspend = NULL,
	.dtps_resume = NULL,
	.dtps_getargdesc = sdt_getargdesc,
#ifdef CONFIG_SPARC64
	.dtps_getargval = NULL,
#else
	.dtps_getargval = sdt_getarg,
#endif
	.dtps_usermode = NULL,
	.dtps_destroy = sdt_destroy,
};

struct dtrace_mprovider sdt_providers[] = {
  { "vtrace", "__vtrace_", &vtrace_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sysinfo", "__cpu_sysinfo_", &info_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "vminfo", "__cpu_vminfo_", &info_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fpuinfo", "__fpuinfo_", &fpu_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sched", "__sched_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "proc", "__proc_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "io", "__io_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "ip", "__ip_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "lockstat", "__lockstat_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "tcp", "__tcp_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "udp", "__udp_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "mib", "__mib_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fsinfo", "__fsinfo_", &fsinfo_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "iscsi", "__iscsi_", &iscsi_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "nfsv3", "__nfsv3_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "nfsv4", "__nfsv4_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "xpv", "__xpv_", &xpv_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fc", "__fc_", &fc_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "srp", "__srp_", &fc_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sysevent", "__sysevent_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "perf", "__perf_", &perf_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sdt", NULL, &sdt_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { NULL }
};

DT_MULTI_PROVIDER_MODULE(sdt, sdt_providers)
