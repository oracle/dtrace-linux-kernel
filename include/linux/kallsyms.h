/* SPDX-License-Identifier: GPL-2.0 */
/* Rewritten and vastly simplified by Rusty Russell for in-kernel
 * module loader:
 *   Copyright 2002 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 */
#ifndef _LINUX_KALLSYMS_H
#define _LINUX_KALLSYMS_H

#include <linux/errno.h>
#include <linux/buildid.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <asm/sections.h>

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s %s]") + \
			(KSYM_NAME_LEN - 1) + \
			2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + \
			(BUILD_ID_SIZE_MAX * 2) + 1)

struct cred;
struct module;

static inline int is_kernel_inittext(unsigned long addr)
{
	if (addr >= (unsigned long)_sinittext
	    && addr <= (unsigned long)_einittext)
		return 1;
	return 0;
}

static inline int is_kernel_text(unsigned long addr)
{
	if ((addr >= (unsigned long)_stext && addr <= (unsigned long)_etext) ||
	    arch_is_kernel_text(addr))
		return 1;
	return in_gate_area_no_mm(addr);
}

static inline int is_kernel(unsigned long addr)
{
	if (addr >= (unsigned long)_stext && addr <= (unsigned long)_end)
		return 1;
	return in_gate_area_no_mm(addr);
}

static inline int is_ksym_addr(unsigned long addr)
{
	if (IS_ENABLED(CONFIG_KALLSYMS_ALL))
		return is_kernel(addr);

	return is_kernel_text(addr) || is_kernel_inittext(addr);
}

static inline void *dereference_symbol_descriptor(void *ptr)
{
#ifdef HAVE_DEREFERENCE_FUNCTION_DESCRIPTOR
	struct module *mod;

	ptr = dereference_kernel_function_descriptor(ptr);
	if (is_ksym_addr((unsigned long)ptr))
		return ptr;

	preempt_disable();
	mod = __module_address((unsigned long)ptr);
	preempt_enable();

	if (mod)
		ptr = dereference_module_function_descriptor(mod, ptr);
#endif
	return ptr;
}

/* To avoid using get_symbol_offset for every symbol, we carry prefix along. */
struct kallsym_iter {
	loff_t pos;
	loff_t pos_arch_end;
	loff_t pos_mod_end;
	loff_t pos_ftrace_mod_end;
	loff_t pos_bpf_end;
	unsigned long value;
	unsigned int nameoff; /* If iterating in core kernel symbols. */
	unsigned long size;
	char type;
	char name[KSYM_NAME_LEN];
	char module_name[MODULE_NAME_LEN];
	const char *builtin_module_names;
	unsigned long hint_builtin_module_idx;
	int exported;
	int show_value;
};

int kallsyms_on_each_symbol(int (*fn)(void *, const char *, struct module *,
				      unsigned long),
			    void *data);

#ifdef CONFIG_KALLSYMS
/* Lookup the address for a symbol. Returns 0 if not found. */
unsigned long kallsyms_lookup_name(const char *name);

extern int kallsyms_lookup_size_offset(unsigned long addr,
				  unsigned long *symbolsize,
				  unsigned long *offset);

/* Lookup an address.  modname is set to NULL if it's in the kernel. */
const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname, char *namebuf);

/* Look up a kernel symbol and return it in a text buffer. */
extern int sprint_symbol(char *buffer, unsigned long address);
extern int sprint_symbol_build_id(char *buffer, unsigned long address);
extern int sprint_symbol_no_offset(char *buffer, unsigned long address);
extern int sprint_backtrace(char *buffer, unsigned long address);
extern int sprint_backtrace_build_id(char *buffer, unsigned long address);

int lookup_symbol_name(unsigned long addr, char *symname);
int lookup_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name);

/* How and when do we show kallsyms values? */
extern bool kallsyms_show_value(const struct cred *cred);

void kallsyms_iter_reset(struct kallsym_iter *iter, loff_t new_pos);
int kallsyms_iter_update(struct kallsym_iter *iter, loff_t pos, int kallmodsyms);

#else /* !CONFIG_KALLSYMS */

static inline unsigned long kallsyms_lookup_name(const char *name)
{
	return 0;
}

static inline int kallsyms_lookup_size_offset(unsigned long addr,
					      unsigned long *symbolsize,
					      unsigned long *offset)
{
	return 0;
}

static inline const char *kallsyms_lookup(unsigned long addr,
					  unsigned long *symbolsize,
					  unsigned long *offset,
					  char **modname, char *namebuf)
{
	return NULL;
}

static inline int sprint_symbol(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_symbol_build_id(char *buffer, unsigned long address)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_symbol_no_offset(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_backtrace(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_backtrace_build_id(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int lookup_symbol_name(unsigned long addr, char *symname)
{
	return -ERANGE;
}

static inline int lookup_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name)
{
	return -ERANGE;
}

static inline bool kallsyms_show_value(const struct cred *cred)
{
	return false;
}

#endif /*CONFIG_KALLSYMS*/

static inline void print_ip_sym(const char *loglvl, unsigned long ip)
{
	printk("%s[<%px>] %pS\n", loglvl, (void *) ip, (void *) ip);
}

#endif /*_LINUX_KALLSYMS_H*/
