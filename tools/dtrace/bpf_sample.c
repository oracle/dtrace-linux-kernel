// SPDX-License-Identifier: GPL-2.0
/*
 * This sample DTrace BPF tracing program demonstrates how actions can be
 * associated with different probe types.
 *
 * The kprobe/ksys_write probe is a Function Boundary Tracing (FBT) entry probe
 * on the ksys_write(fd, buf, count) function in the kernel.  Arguments to the
 * function can be retrieved from the CPU registers (struct pt_regs).
 *
 * The tracepoint/syscalls/sys_enter_write probe is a System Call entry probe
 * for the write(d, buf, count) system call.  Arguments to the system call can
 * be retrieved from the tracepoint data passed to the BPF program as context
 * struct syscall_data) when the probe fires.
 *
 * The BPF program associated with each probe prepares a DTrace BPF context
 * (struct dt_bpf_context) that stores the probe ID and up to 10 arguments.
 * Only 3 arguments are used in this sample.  Then the prorgams call a shared
 * BPF function (bpf_action) that implements the actual action to be taken when
 * a probe fires.  It prepares a data record to be stored in the tracing buffer
 * and submits it to the buffer.  The data in the data record is obtained from
 * the DTrace BPF context.
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */
#include <uapi/linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/unistd.h>
#include "bpf_helpers.h"

#include "dtrace.h"

struct syscall_data {
	struct pt_regs *regs;
	long syscall_nr;
	long arg[6];
};

struct bpf_map_def SEC("maps") buffers = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = NR_CPUS,
};

#if defined(bpf_target_x86)
# define PT_REGS_PARM6(x)	((x)->r9)
#elif defined(bpf_target_s390x)
# define PT_REGS_PARM6(x)	((x)->gprs[7])
#elif defined(bpf_target_arm)
# define PT_REGS_PARM6(x)	((x)->uregs[5])
#elif defined(bpf_target_arm64)
# define PT_REGS_PARM6(x)	((x)->regs[5])
#elif defined(bpf_target_mips)
# define PT_REGS_PARM6(x)	((x)->regs[9])
#elif defined(bpf_target_powerpc)
# define PT_REGS_PARM6(x)	((x)->gpr[8])
#elif defined(bpf_target_sparc)
# define PT_REGS_PARM6(x)	((x)->u_regs[UREG_I5])
#else
# error Argument retrieval from pt_regs is not supported yet on this arch.
#endif

/*
 * We must pass a valid BPF context pointer because the bpf_perf_event_output()
 * helper requires a BPF context pointer as first argument (and the verifier is
 * validating that we pass a value that is known to be a context pointer).
 *
 * This BPF function implements the following D action:
 * {
 *	trace(curthread);
 *	trace(arg0);
 *	trace(arg1);
 *	trace(arg2);
 * }
 *
 * Expected output will look like:
 *   CPU     ID
 *    15  70423 0xffff8c0968bf8ec0 0x00000000000001 0x0055e019eb3f60 0x0000000000002c
 *    15  18876 0xffff8c0968bf8ec0 0x00000000000001 0x0055e019eb3f60 0x0000000000002c
 *    |   |     +-- curthread      +--> arg0 (fd)   +--> arg1 (buf)  +-- arg2 (count)
 *    |   |
 *    |   +--> probe ID
 *    |
 *    +--> CPU the probe fired on
 */
static noinline int bpf_action(void *bpf_ctx, struct dt_bpf_context *ctx)
{
	int			cpu = bpf_get_smp_processor_id();
	struct data {
		u32	probe_id;	/* mandatory */

		u64	task;		/* first data item (current task) */
		u64	arg0;		/* 2nd data item (arg0, fd) */
		u64	arg1;		/* 3rd data item (arg1, buf) */
		u64	arg2;		/* 4th data item (arg2, count) */
	}			rec;

	memset(&rec, 0, sizeof(rec));

	rec.probe_id = ctx->probe_id;
	rec.task = bpf_get_current_task();
	rec.arg0 = ctx->argv[0];
	rec.arg1 = ctx->argv[1];
	rec.arg2 = ctx->argv[2];

	bpf_perf_event_output(bpf_ctx, &buffers, cpu, &rec, sizeof(rec));

	return 0;
}

SEC("kprobe/ksys_write")
int bpf_kprobe(struct pt_regs *regs)
{
	struct dt_bpf_context	ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.probe_id = 18876;
	ctx.argv[0] = PT_REGS_PARM1(regs);
	ctx.argv[1] = PT_REGS_PARM2(regs);
	ctx.argv[2] = PT_REGS_PARM3(regs);
	ctx.argv[3] = PT_REGS_PARM4(regs);
	ctx.argv[4] = PT_REGS_PARM5(regs);
	ctx.argv[5] = PT_REGS_PARM6(regs);

	return bpf_action(regs, &ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int bpf_tp(struct syscall_data *scd)
{
	struct dt_bpf_context	ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.probe_id = 70423;
	ctx.argv[0] = scd->arg[0];
	ctx.argv[1] = scd->arg[1];
	ctx.argv[2] = scd->arg[2];

	return bpf_action(scd, &ctx);
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
