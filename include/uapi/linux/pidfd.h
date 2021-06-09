/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_PIDFD_H
#define _UAPI_LINUX_PIDFD_H

#include <linux/types.h>
#include <linux/fcntl.h>

/* Flags for pidfd_open().  */
#define PIDFD_NONBLOCK O_NONBLOCK

/* An arbitrary value unlikely ever to be useful for pidfds.  */
#define PIDFD_THREAD O_NOCTTY

#endif /* _UAPI_LINUX_PIDFD_H */
