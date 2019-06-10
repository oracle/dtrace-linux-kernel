// SPDX-License-Identifier: GPL-2.0
/*
 * This file provides the tracing buffer handling for DTrace.  It makes use of
 * the perf event output ring buffers that can be written to from BPF programs.
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>

#include "dtrace_impl.h"

/*
 * Probe data is recorded in per-CPU perf ring buffers.
 */
struct dtrace_buffer {
	int	cpu;			/* ID of CPU that uses this buffer */
	int	fd;			/* fd of perf output buffer */
	size_t	page_size;		/* size of each page in buffer */
	size_t	data_size;		/* total buffer size */
	u8	*base;			/* address of buffer */
	u8	*endp;			/* address of end of buffer */
	u8	*tmp;			/* temporary event buffer */
	u32	tmp_len;		/* length of temporary event buffer */
};

static struct dtrace_buffer	*dt_buffers;

/*
 * File descriptor for the BPF map that holds the buffers for the online CPUs.
 * The map is a bpf_array indexed by CPU id, and it stores a file descriptor as
 * value (the fd for the perf_event that represents the CPU buffer).
 */
int				dt_bufmap_fd = -1;

/*
 * Create a perf_event buffer for the given DTrace buffer.  This will create
 * a perf_event ring_buffer, mmap it, and enable the perf_event that owns the
 * buffer.
 */
static int perf_buffer_open(struct dtrace_buffer *buf)
{
	int			pefd;
	struct perf_event_attr	attr = {};

	/*
	 * Event configuration for BPF-generated output in perf_event ring
	 * buffers.  The event is created in enabled state.
	 */
	attr.config = PERF_COUNT_SW_BPF_OUTPUT;
	attr.type = PERF_TYPE_SOFTWARE;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	pefd = perf_event_open(&attr, -1, buf->cpu, -1, PERF_FLAG_FD_CLOEXEC);
	if (pefd < 0) {
		fprintf(stderr, "perf_event_open(cpu %d): %s\n", buf->cpu,
			strerror(errno));
		goto fail;
	}

	/*
	 * We add buf->page_size to the buf->data_size, because perf maintains
	 * a meta-data page at the beginning of the memory region.  That page
	 * is used for reader/writer symchronization.
	 */
	buf->fd = pefd;
	buf->base = mmap(NULL, buf->page_size + buf->data_size,
			 PROT_READ | PROT_WRITE, MAP_SHARED, buf->fd, 0);
	buf->endp = buf->base + buf->page_size + buf->data_size - 1;
	if (!buf->base)
		goto fail;

	return 0;

fail:
	if (buf->base) {
		munmap(buf->base, buf->page_size + buf->data_size);
		buf->base = NULL;
		buf->endp = NULL;
	}
	if (buf->fd) {
		close(buf->fd);
		buf->fd = -1;
	}

	return -1;
}

/*
 * Close the given DTrace buffer.  This function disables the perf_event that
 * owns the buffer, munmaps the memory space, and closes the perf buffer fd.
 */
static void perf_buffer_close(struct dtrace_buffer *buf)
{
	/*
	 * If the perf buffer failed to open, there is no need to close it.
	 */
	if (buf->fd < 0)
		return;

	if (ioctl(buf->fd, PERF_EVENT_IOC_DISABLE, 0) < 0)
		fprintf(stderr, "PERF_EVENT_IOC_DISABLE(cpu %d): %s\n",
			buf->cpu, strerror(errno));

	munmap(buf->base, buf->page_size + buf->data_size);

	if (close(buf->fd))
		fprintf(stderr, "perf buffer close(cpu %d): %s\n",
			buf->cpu, strerror(errno));

	buf->base = NULL;
	buf->fd = -1;
}

/*
 * Initialize the probe data buffers (one per online CPU).  Each buffer will
 * contain the given number of pages (i.e. total size of each buffer will be
 * num_pages * getpagesize()).  This function also sets up an event polling
 * descriptor that monitors all CPU buffers at once.
 */
int dt_buffer_init(int num_pages)
{
	int	i;
	int	epoll_fd;

	if (dt_bufmap_fd < 0)
		return -EINVAL;

	/* Allocate the per-CPU buffer structs. */
	dt_buffers = calloc(dt_numcpus, sizeof(struct dtrace_buffer));
	if (dt_buffers == NULL)
		return -ENOMEM;

	/* Set up the event polling file descriptor. */
	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		free(dt_buffers);
		return -errno;
	}

	for (i = 0; i < dt_numcpus; i++) {
		int			cpu = dt_cpuids[i];
		struct epoll_event	ev;
		struct dtrace_buffer	*buf = &dt_buffers[i];

		buf->cpu = cpu;
		buf->page_size = getpagesize();
		buf->data_size = num_pages * buf->page_size;
		buf->tmp = NULL;
		buf->tmp_len = 0;

		/* Try to create the perf buffer for this DTrace buffer. */
		if (perf_buffer_open(buf) == -1)
			continue;

		/* Store the perf buffer fd in the buffer map. */
		dt_bpf_map_update(dt_bufmap_fd, &cpu, &buf->fd);

		/* Add the buffer to the event polling descriptor. */
		ev.events = EPOLLIN;
		ev.data.ptr = buf;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, buf->fd, &ev) == -1) {
			fprintf(stderr, "EPOLL_CTL_ADD(cpu %d): %s\n",
				buf->cpu, strerror(errno));
			continue;
		}
	}

	return epoll_fd;
}

/*
 * Clean up the buffers.
 */
void dt_buffer_exit(int epoll_fd)
{
	int	i;

	for (i = 0; i < dt_numcpus; i++)
		perf_buffer_close(&dt_buffers[i]);

	free(dt_buffers);
	close(epoll_fd);
}

/*
 * Process and output the probe data at the supplied address.
 */
static void output_event(int cpu, u64 *buf)
{
	u8				*data = (u8 *)buf;
	struct perf_event_header	*hdr;

	hdr = (struct perf_event_header *)data;
	data += sizeof(struct perf_event_header);

	if (hdr->type == PERF_RECORD_SAMPLE) {
		u8		*ptr = data;
		u32		i, size, probe_id;

		/*
		 * struct {
		 *	struct perf_event_header	header;
		 *	u32				size;
		 *	u32				probe_id;
		 *	u32				gap;
		 *	u64				data[n];
		 * }
		 * and data points to the 'size' member at this point.
		 */
		if (ptr > (u8 *)buf + hdr->size) {
			fprintf(stderr, "BAD: corrupted sample header\n");
			return;
		}

		size = *(u32 *)data;
		data += sizeof(size);
		ptr += sizeof(size) + size;
		if (ptr != (u8 *)buf + hdr->size) {
			fprintf(stderr, "BAD: invalid sample size\n");
			return;
		}

		probe_id = *(u32 *)data;
		data += sizeof(probe_id);
		size -= sizeof(probe_id);
		data += sizeof(u32);		/* skip 32-bit gap */
		size -= sizeof(u32);
		buf = (u64 *)data;

		printf("%3d %6d ", cpu, probe_id);
		for (i = 0, size /= sizeof(u64); i < size; i++)
			printf("%#016lx ", buf[i]);
		printf("\n");
	} else if (hdr->type == PERF_RECORD_LOST) {
		u64	lost;

		/*
		 * struct {
		 *	struct perf_event_header	header;
		 *	u64				id;
		 *	u64				lost;
		 * }
		 * and data points to the 'id' member at this point.
		 */
		lost = *(u64 *)(data + sizeof(u64));

		printf("[%ld probes dropped]\n", lost);
	} else
		fprintf(stderr, "UNKNOWN: record type %d\n", hdr->type);
}

/*
 * Process the available probe data in the given buffer.
 */
static void process_data(struct dtrace_buffer *buf)
{
	struct perf_event_mmap_page	*rb_page = (void *)buf->base;
	struct perf_event_header	*hdr;
	u8				*base;
	u64				head, tail;

	/* Set base to be the start of the buffer data. */
	base = buf->base + buf->page_size;

	for (;;) {
		head = ring_buffer_read_head(rb_page);
		tail = rb_page->data_tail;

		if (tail == head)
			break;

		do {
			u8	*event = base + tail % buf->data_size;
			u32	len;

			hdr = (struct perf_event_header *)event;
			len = hdr->size;

			/*
			 * If the perf event data wraps around the boundary of
			 * the buffer, we make a copy in contiguous memory.
			 */
			if (event + len > buf->endp) {
				u8	*dst;
				u32	num;

				/* Increase buffer as needed. */
				if (buf->tmp_len < len) {
					buf->tmp = realloc(buf->tmp, len);
					buf->tmp_len = len;
				}

				dst = buf->tmp;
				num = buf->endp - event + 1;
				memcpy(dst, event, num);
				memcpy(dst + num, base, len - num);

				event = dst;
			}

			output_event(buf->cpu, (u64 *)event);

			tail += hdr->size;
		} while (tail != head);

		ring_buffer_write_tail(rb_page, tail);
	}
}

/*
 * Wait for data to become available in any of the buffers.
 */
int dt_buffer_poll(int epoll_fd, int timeout)
{
	struct epoll_event	events[dt_numcpus];
	int			i, cnt;

	cnt = epoll_wait(epoll_fd, events, dt_numcpus, timeout);
	if (cnt < 0)
		return -errno;

	for (i = 0; i < cnt; i++)
		process_data((struct dtrace_buffer *)events[i].data.ptr);

	return cnt;
}
