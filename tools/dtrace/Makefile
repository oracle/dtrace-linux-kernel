# SPDX-License-Identifier: GPL-2.0
#
# This Makefile is based on samples/bpf.
#
# Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.

DT_VERSION		:= 2.0.0
DT_GIT_VERSION		:= $(shell git rev-parse HEAD 2>/dev/null || \
				   echo Unknown)

DTRACE_PATH		?= $(abspath $(srctree)/$(src))
TOOLS_PATH		:= $(DTRACE_PATH)/..
SAMPLES_PATH		:= $(DTRACE_PATH)/../../samples

hostprogs-y		:= dtrace

LIBBPF			:= $(TOOLS_PATH)/lib/bpf/libbpf.a
OBJS			:= dt_bpf.o dt_buffer.o dt_utils.o dt_probe.o \
			   dt_hash.o \
			   dt_fbt.o dt_syscall.o

dtrace-objs		:= $(OBJS) dtrace.o

always			:= $(hostprogs-y)
always			+= bpf_sample.o

KBUILD_HOSTCFLAGS	+= -DDT_VERSION=\"$(DT_VERSION)\"
KBUILD_HOSTCFLAGS	+= -DDT_GIT_VERSION=\"$(DT_GIT_VERSION)\"
KBUILD_HOSTCFLAGS	+= -I$(srctree)/tools/lib
KBUILD_HOSTCFLAGS	+= -I$(srctree)/tools/include/uapi
KBUILD_HOSTCFLAGS	+= -I$(srctree)/tools/include/
KBUILD_HOSTCFLAGS	+= -I$(srctree)/usr/include

KBUILD_HOSTLDLIBS	:= $(LIBBPF) -lelf

LLC			?= llc
CLANG			?= clang
LLVM_OBJCOPY		?= llvm-objcopy

ifdef CROSS_COMPILE
HOSTCC			= $(CROSS_COMPILE)gcc
CLANG_ARCH_ARGS		= -target $(ARCH)
endif

all:
	$(MAKE) -C ../../ $(CURDIR)/ DTRACE_PATH=$(CURDIR)

clean:
	$(MAKE) -C ../../ M=$(CURDIR) clean
	@rm -f *~

$(LIBBPF): FORCE
	$(MAKE) -C $(dir $@) RM='rm -rf' LDFLAGS= srctree=$(DTRACE_PATH)/../../ O=

FORCE:

.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(DTRACE_PATH)/*.c: verify_target_bpf $(LIBBPF)
$(src)/*.c: verify_target_bpf $(LIBBPF)

$(obj)/%.o: $(src)/%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) -I$(obj) \
		-I$(srctree)/tools/testing/selftests/bpf/ \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-I$(srctree)/samples/bpf/ -include asm_goto_workaround.h \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@
