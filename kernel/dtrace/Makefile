#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#

DT_CORE_ARCH_OBJS		= $(addprefix ../../arch/$(SRCARCH)/kernel/, \
				    dtrace_util.o)

ifdef CONFIG_DT_CORE
obj-y				+= cyclic.o dtrace_os.o dtrace_cpu.o \
				   dtrace_task.o dtrace_psinfo.o \
				   $(DT_CORE_ARCH_OBJS)
endif
