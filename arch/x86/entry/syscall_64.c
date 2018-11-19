// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL

#define __SYSCALL(nr, sym) __x64_##sym,

#if IS_ENABLED(CONFIG_DT_SYSTRACE)
asmlinkage sys_call_ptr_t sys_call_table[] = {
#else
asmlinkage const sys_call_ptr_t sys_call_table[] = {
#endif
#include <asm/syscalls_64.h>
};
