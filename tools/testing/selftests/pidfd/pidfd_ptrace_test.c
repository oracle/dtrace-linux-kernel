// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include "pidfd.h"
#include "../kselftest.h"

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL           (1 << 20)
#endif

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_NOCTTY
#endif

int main(int argc, char **argv)
{
	int pidfd, forkblock[2];
	pid_t pid;
	int ret = 1;
	struct pollfd pfd[1];

	ksft_set_plan(1);

	if (pipe(forkblock) < 0) {
		ksft_print_msg("%s - failed to set up pipes\n", strerror(errno));
		goto on_error;
	}

	if ((pid = fork()) < 0) {
		ksft_print_msg("%s - failed to fork\n", strerror(errno));
		goto on_error;
	}

	if (pid == 0) { /* child */
		int dummy;
		close(forkblock[1]);
		read(forkblock[0], &dummy, 1);
		close(forkblock[0]);
		execlp("true", "true", NULL);
		_exit(127);
	}
	close(forkblock[0]);

	if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL |
		   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT) < 0) {
		ksft_print_msg("%s - failed to ptrace\n");
		kill(pid, SIGKILL);
		goto on_error;
	}
	close(forkblock[1]);

	pidfd = sys_pidfd_open(pid, PIDFD_THREAD);
	if (pidfd < 0) {
		ksft_print_msg(
			"%s - failed to to open pidfd for pid %i\n",
			strerror(errno), pid);
		goto on_error;
	}

	pfd[0].events = POLLIN;
	pfd[0].fd = pidfd;

	while (errno = EINTR,
	       poll((struct pollfd *) pfd, 1, 10000) <= 0 && errno == EINTR)
		continue;

	if (pfd[0].revents == 0) {
		ksft_test_result_fail("timed out: pfd polling insensitive to ptrace awakens: failed\n");
	} else {
		ksft_test_result_pass("pfd polling sensitive to ptrace awakens: passed\n");
	}

	ret = 0;

on_error:
	if (pidfd >= 0)
		close(pidfd);

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
