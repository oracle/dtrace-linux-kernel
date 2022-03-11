/* SPDX-License-Identifier: UPL-1.0 */
/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_METADESC_H
#define _LINUX_DTRACE_METADESC_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/actions_defines.h>
#include <linux/dtrace/metadesc_defines.h>

/*
 * DTrace separates the trace data stream from the metadata stream.  The only
 * metadata tokens placed in the data stream are enabled probe identifiers
 * (EPIDs) or (in the case of aggregations) aggregation identifiers.  In order
 * to determine the structure of the data, DTrace consumers pass the token to
 * the kernel, and receive in return a corresponding description of the enabled
 * probe (via the dtrace_eprobedesc structure) or the aggregation (via the
 * dtrace_aggdesc structure).  Both of these structures are expressed in terms
 * of record descriptions (via the dtrace_recdesc structure) that describe the
 * exact structure of the data.  Some record descriptions may also contain a
 * format identifier; this additional bit of metadata can be retrieved from the
 * kernel, for which a format description is returned via the dtrace_fmtdesc
 * structure.  Note that all four of these structures must be bitness-neutral
 * to allow for a 32-bit DTrace consumer on a 64-bit kernel.
 */
typedef struct dtrace_recdesc {
	dtrace_actkind_t dtrd_action;		/* kind of action */
	uint32_t dtrd_size;			/* size of record */
	uint32_t dtrd_offset;			/* offset in ECB's data */
	uint16_t dtrd_alignment;		/* required alignment */
	uint16_t dtrd_format;			/* format, if any */
	uint64_t dtrd_arg;			/* action argument */
	uint64_t dtrd_uarg;			/* user argument */
} dtrace_recdesc_t;

typedef struct dtrace_eprobedesc {
	dtrace_epid_t dtepd_epid;		/* enabled probe ID */
	dtrace_id_t dtepd_probeid;		/* probe ID */
	uint64_t dtepd_uarg;			/* library argument */
	uint32_t dtepd_size;			/* total size */
	int dtepd_nrecs;			/* number of records */
	struct dtrace_recdesc dtepd_rec[1];	/* records themselves */
} dtrace_eprobedesc_t;

typedef struct dtrace_aggdesc {
	DTRACE_PTR(char, dtagd_name);		/* not filled in by kernel */
	dtrace_aggvarid_t dtagd_varid;		/* not filled in by kernel */
	int dtagd_flags;			/* not filled in by kernel */
	dtrace_aggid_t dtagd_id;		/* aggregation ID */
	dtrace_epid_t dtagd_epid;		/* enabled probe ID */
	uint32_t dtagd_size;			/* size in bytes */
	int dtagd_nrecs;			/* number of records */
	uint32_t dtagd_pad;			/* explicit padding */
	struct dtrace_recdesc dtagd_rec[1];	/* record descriptions */
} dtrace_aggdesc_t;

typedef struct dtrace_fmtdesc {
	DTRACE_PTR(char, dtfd_string);		/* format string */
	int dtfd_length;			/* length of format string */
	uint16_t dtfd_format;			/* format identifier */
} dtrace_fmtdesc_t;

#define DTRACE_SIZEOF_EPROBEDESC(desc)				\
	(sizeof(struct dtrace_eprobedesc) + ((desc)->dtepd_nrecs ?  \
	(((desc)->dtepd_nrecs - 1) * sizeof(struct dtrace_recdesc)) : 0))

#define	DTRACE_SIZEOF_AGGDESC(desc)			       \
	(sizeof(struct dtrace_aggdesc) + ((desc)->dtagd_nrecs ?     \
	(((desc)->dtagd_nrecs - 1) * sizeof(struct dtrace_recdesc)) : 0))

#endif /* _LINUX_DTRACE_METADESC_H */
