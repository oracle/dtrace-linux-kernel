// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/log2.h>

#include "dtrace_impl.h"

#define DTRACE_BUFSIZE	32		/* default buffer size (in pages) */

#define DMODE_VERS	0		/* display version information (-V) */
#define DMODE_LIST	1		/* list probes (-l) */
#define DMODE_EXEC	2		/* compile program and start tracing */

#define E_SUCCESS	0
#define E_ERROR		1
#define E_USAGE		2

#define NUM_PAGES(sz)	(((sz) + getpagesize() - 1) / getpagesize())

static const char		*dtrace_options = "+b:ls:V";

static char			*g_pname;
static int			g_mode = DMODE_EXEC;

static int usage(void)
{
	fprintf(stderr, "Usage: %s [-lV] [-b bufsz] -s script\n", g_pname);
	fprintf(stderr,
	"\t-b  set trace buffer size\n"
	"\t-l  list probes matching specified criteria\n"
	"\t-s  enable or list probes for the specified BPF program\n"
	"\t-V  report DTrace API version\n");

	return E_USAGE;
}

static u64 parse_size(const char *arg)
{
	long long	mul = 1;
	long long	neg, val;
	size_t		len;
	char		*end;

	if (!arg)
		return -1;

	len = strlen(arg);
	if (!len)
		return -1;

	switch (arg[len - 1]) {
	case 't':
	case 'T':
		mul *= 1024;
		/* fall-through */
	case 'g':
	case 'G':
		mul *= 1024;
		/* fall-through */
	case 'm':
	case 'M':
		mul *= 1024;
		/* fall-through */
	case 'k':
	case 'K':
		mul *= 1024;
		/* fall-through */
	default:
		break;
	}

	neg = strtoll(arg, NULL, 0);
	errno = 0;
	val = strtoull(arg, &end, 0) * mul;

	if ((mul > 1 && end != &arg[len - 1]) || (mul == 1 && *end != '\0') ||
	    val < 0 || neg < 0 || errno != 0)
		return -1;

	return val;
}

int main(int argc, char *argv[])
{
	int	i;
	int	modec = 0;
	int	bufsize = DTRACE_BUFSIZE;
	int	epoll_fd;
	int	cnt;
	char	**prgv;
	int	prgc;

	g_pname = basename(argv[0]);

	if (argc == 1)
		return usage();

	prgc = 0;
	prgv = calloc(argc, sizeof(char *));
	if (!prgv) {
		fprintf(stderr, "failed to allocate memory for arguments: %s\n",
			strerror(errno));
		return E_ERROR;
	}

	argv[0] = g_pname;			/* argv[0] for getopt errors */

	for (optind = 1; optind < argc; optind++) {
		int	opt;

		while ((opt = getopt(argc, argv, dtrace_options)) != EOF) {
			u64			val;

			switch (opt) {
			case 'b':
				val = parse_size(optarg);
				if (val < 0) {
					fprintf(stderr, "invalid: -b %s\n",
						optarg);
					return E_ERROR;
				}

				/*
				 * Bufsize needs to be a number of pages, and
				 * must be a power of 2.  This is required by
				 * the perf event buffer code.
				 */
				bufsize = roundup_pow_of_two(NUM_PAGES(val));
				if ((u64)bufsize * getpagesize() > val)
					fprintf(stderr,
						"bufsize increased to %ld\n",
						(u64)bufsize * getpagesize());

				break;
			case 'l':
				g_mode = DMODE_LIST;
				modec++;
				break;
			case 's':
				prgv[prgc++] = optarg;
				break;
			case 'V':
				g_mode = DMODE_VERS;
				modec++;
				break;
			default:
				if (strchr(dtrace_options, opt) == NULL)
					return usage();
			}
		}

		if (optind < argc) {
			fprintf(stderr, "unknown option '%s'\n", argv[optind]);
			return E_ERROR;
		}
	}

	if (modec > 1) {
		fprintf(stderr,
			"only one of [-lV] can be specified at a time\n");
		return E_USAGE;
	}

	/*
	 * We handle requests for version information first because we do not
	 * need probe information for it.
	 */
	if (g_mode == DMODE_VERS) {
		printf("%s\n"
		       "This is DTrace %s\n"
		       "dtrace(1) version-control ID: %s\n",
		       DT_VERS_STRING, DT_VERSION, DT_GIT_VERSION);

		return E_SUCCESS;
	}

	/* Initialize probes. */
	if (dt_probe_init() < 0) {
		fprintf(stderr, "failed to initialize probes: %s\n",
			strerror(errno));
		return E_ERROR;
	}

	/*
	 * We handle requests to list probes next.
	 */
	if (g_mode == DMODE_LIST) {
		int	rc = 0;

		printf("%5s %10s %17s %33s %s\n",
		       "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");
		for (i = 0; i < prgc; i++) {
			rc = dt_bpf_list_probes(prgv[i]);
			if (rc < 0)
				fprintf(stderr, "failed to load %s: %s\n",
					prgv[i], strerror(errno));
		}

		return rc ? E_ERROR : E_SUCCESS;
	}

	if (!prgc) {
		fprintf(stderr, "missing BPF program(s)\n");
		return E_ERROR;
	}

	/* Process the BPF program. */
	for (i = 0; i < prgc; i++) {
		int	err;

		err = dt_bpf_load_file(prgv[i]);
		if (err) {
			errno = -err;
			fprintf(stderr, "failed to load %s: %s\n",
				prgv[i], strerror(errno));
			return E_ERROR;
		}
	}

	/* Get the list of online CPUs. */
	cpu_list_populate();

	/* Initialize buffers. */
	epoll_fd = dt_buffer_init(bufsize);
	if (epoll_fd < 0) {
		errno = -epoll_fd;
		fprintf(stderr, "failed to allocate buffers: %s\n",
			strerror(errno));
		return E_ERROR;
	}

	/* Process probe data. */
	printf("%3s %6s\n", "CPU", "ID");
	do {
		cnt = dt_buffer_poll(epoll_fd, 100);
	} while (cnt >= 0);

	dt_buffer_exit(epoll_fd);

	return E_SUCCESS;
}
