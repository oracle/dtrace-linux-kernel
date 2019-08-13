#!/bin/sh

# Oracle Linux DTrace.
# Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#

# Oracle has been working in recent years on porting DTrace, the
# dynamic tracing tool, to Linux.  DTrace offers easy-to-use, powerful,
# safe, and unintrusive tracing.  Oracle's initial focus was the Oracle
# Unbreakable Enterprise Kernel (UEK), but DTrace runs on upstream Linux
# kernels and other distributions' Linux kernels as well.  Note that at
# the moment, Oracle is in the process of upstreaming DTrace-related work
# and reimplementing DTrace itself on top of existing kernel infrastructure
# such as eBPF.

# This script illustrates how to build DTrace on Fedora on x86.
# It is intended as a tutorial rather than a robust, turn-key utility.
# Read and understand the steps as you execute them.  The steps are
# similar to what one does to build DTrace on other Linux distributions.

# Useful references on building a custom Fedora kernel include:
# https://fedoraproject.org/wiki/Building_a_custom_kernel
# https://fedoraproject.org/wiki/Building_a_custom_kernel#Building_Vanilla_upstream_kernel
# Roughly speaking, you should have about 20 Gbyte of disk space
# available and expect to wait a few hours for the build to complete.

# The overall process is:
#   1. download and build the CTF library for DTrace to use
#   2. download Fedora kernel source code
#   3. prepare DTrace patches to apply
#   4. prepare the kernel source code
#      a. Linux base code
#      b. apply Linux patches (if any)
#      c. apply Fedora patches
#      d. apply DTrace patches
#      e. prepare makefile and config
#   5. build the kernel
#   6. reboot
#   7. download and build the DTrace userspace utility


# pick one
# DTrace patches change relatively infrequently.
# So DTrace_branch might not have to match your Fedora kernel version exactly.
#fedora_release=f29; DTrace_branch=5.2.7 ; num_DTrace_patches=19
 fedora_release=f30; DTrace_branch=5.2.7 ; num_DTrace_patches=19

# Step 1: download and build the CTF library for DTrace to use

sudo dnf install -y git
git clone https://github.com/oracle/libdtrace-ctf.git
cd libdtrace-ctf
sudo dnf builddep -y libdtrace-ctf.spec # install dependencies
make
sudo make install
cd ..

# Step 2: download Fedora kernel source code

sudo dnf install -y fedora-packager
fedpkg co -a kernel                     # anonymous clone of Fedora patches
cd kernel
git checkout origin/$fedora_release
fedpkg sources                          # download tarballs of kernel sources
sudo dnf builddep -y kernel.spec        # install dependencies
cd ..

# Step 3: prepare DTrace patches to apply

# download DTrace kernel code
git clone https://github.com/oracle/dtrace-linux-kernel.git
cd dtrace-linux-kernel/
git checkout origin/$DTrace_branch

# The DTrace patches will be the most recent commits.
# Make sure you use all of them but nothing before that.
# Make sure the top patches are DTrace
# and the next one after them is the Linux baseline you want.
# E.g., the top commits here are DTrace, and the last one is Linux upstream:
#     [...]
#     66f76fef08e3 dtrace: modular components and x86 support
#     25f11bb97fb9 dtrace: core and x86
#     3c5af76fa5fb waitfd: new syscall implementing waitpid() over fds
#     e95e4350d02b kallsyms: introduce new /proc/kallmodsyms including builtin modules too
#     86e43efc644c ctf: generate CTF information for the kernel
#     a3b22b9f11d9 (tag: v5.0-rc7) Linux 5.0-rc7
git log -n $(($num_DTrace_patches + 1)) --oneline

# generate the DTrace patches
git format-patch -$num_DTrace_patches

cd ..

# Step 4: prepare the kernel source code

#   Step 4a: Linux base code

if [ -e kernel/linux-*.xz ]; then
    /usr/bin/xz -dc kernel/linux-*.tar.xz | /usr/bin/tar -xof -
else
    tar xzf kernel/linux-*.tar.gz
fi

#   make a git repo so patches can be applied
cd linux-*
git init
git config user.email "kernel-team@fedoraproject.org"
git config user.name "Fedora Kernel Team"
git config gc.auto 0
git add .
git commit -a -q -m "baseline"

#   Step 4b: apply Linux patches (if any)

if [ -e ../kernel/patch-*.xz ]; then
    xzcat ../kernel/patch-*.xz | patch -p1 -F1 -s
    git commit -a -m "Stable update"
fi

#   Step 4c: apply Fedora patches

for x in `awk '/^Patch/ {print $2}' ../kernel/kernel.spec`; do
    git am ../kernel/$x
done

#   Step 4d: apply DTrace patches

for x in ../dtrace-linux-kernel/00*.patch; do
    git am $x
    if [ $? -ne 0 ]; then
        echo DTrace patch did not apply cleanly
        exit 1
    fi
done

#   Step 4e: prepare makefile and config

#   modify the version tag in the Makefile
sed -i.old \
  's/^EXTRAVERSION =.*$/EXTRAVERSION = -200.DTrace_'$fedora_release'.x86_64/' \
  Makefile

#   use the Fedora config file
cp ../kernel/kernel-x86_64.config .config

#   modify the config file for DTrace
sed -i \
  -e 's/# CONFIG_UNWINDER_FRAME_POINTER is not set/CONFIG_UNWINDER_FRAME_POINTER=y/' \
  -e 's/CONFIG_UNWINDER_ORC=y/# CONFIG_UNWINDER_ORC is not set/' .config
echo "CONFIG_DTRACE=y"                    >> .config
echo "CONFIG_DT_CORE=m"                   >> .config
echo "CONFIG_DT_FASTTRAP=m"               >> .config
echo "CONFIG_DT_PROFILE=m"                >> .config
echo "CONFIG_DT_SDT=m"                    >> .config
echo "CONFIG_DT_SDT_PERF=y"               >> .config
echo "CONFIG_DT_FBT=m"                    >> .config
echo "CONFIG_DT_SYSTRACE=m"               >> .config
echo "CONFIG_DT_DT_TEST=m"                >> .config
echo "CONFIG_DT_DT_PERF=m"                >> .config
echo "CONFIG_DT_DEBUG=y"                  >> .config
echo "# CONFIG_DT_DEBUG_MUTEX is not set" >> .config

# Step 5: build the kernel

# (might take hours)
make olddefconfig
make -j4
make -j4 ctf

# install
sudo make modules_install
sudo make install
sudo make INSTALL_HDR_PATH=/usr headers_install
cd ..

# Step 6: reboot

sudo reboot

# Step 7: download and build the DTrace userspace utility

git clone https://github.com/oracle/dtrace-utils.git
cd dtrace-utils

# The DTrace packages are missing from Fedora repos,
# and we just built that software ourselves.
# So eliminate those packages from the .spec file
# before calling dnf builddep.
sed -i.old \
    -e 's/-devel libdtrace-ctf-devel >= [0-9\.]*/-devel/' \
    -e '/^BuildRequires: dtrace-kernel-headers = [0-9\.]*$/d' dtrace-utils.spec
sudo dnf builddep -y dtrace-utils.spec

make
sudo make install
cd ..

exit 0

# Now, we can use DTrace on Fedora!  (Notice that it is installed at /usr/sbin/dtrace.
# Some other utility is at /usr/bin/dtrace.)  You must be logged in as
# root to use DTrace.  The first thing to do is to list the available probes:
#
#     # /usr/sbin/dtrace -l
#         ID   PROVIDER        MODULE                 FUNCTION NAME
#          1     dtrace                                        BEGIN
#          2     dtrace                                        END
#          3     dtrace                                        ERROR
#          5        fbt         isofs              isofs_hashi entry
#          6        fbt         isofs              isofs_hashi return
#          7        fbt         isofs             isofs_statfs entry
#          8        fbt         isofs             isofs_statfs return
#          9        fbt         isofs         isofs_iget5_test entry
#         10        fbt         isofs         isofs_iget5_test return
#     [...thousands of lines omitted...]
#
# Next, check out the Oracle DTrace Guide for simple examples and more information.
# https://docs.oracle.com/cd/E52668_01/E38608/html/index.html

