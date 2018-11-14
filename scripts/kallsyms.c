/* Generate assembler source containing symbol information
 *
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: nm -n -S vmlinux | scripts/kallsyms [--all-symbols]
 *                                            [--symbol-prefix=<prefix char>]
 *                                            [--builtin=modules_thick.builtin]
 *                                            > symbols.S
 *
 *      Table compression uses all the unused char codes on the symbols and
 *  maps these to the most used substrings (tokens). For instance, it might
 *  map char code 0xF7 to represent "write_" and then in every symbol where
 *  "write_" appears it can be replaced by 0xF7, saving 5 bytes.
 *      The used codes themselves are also placed in the table so that the
 *  decompresion can work without "special cases".
 *      Applied to kernel symbols, this usually produces a compression ratio
 *  of about 50%.
 *
 */

#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include "../include/generated/autoconf.h"

#ifdef CONFIG_KALLMODSYMS
#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <glib.h>

#include <eu_simple.h>
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define KSYM_NAME_LEN		128

struct sym_entry {
	unsigned long long addr;
	unsigned long long size;
	unsigned int len;
	unsigned int start_pos;
	unsigned int percpu_absolute;
#ifdef CONFIG_KALLMODSYMS
	unsigned int module;
#endif
	unsigned char sym[0];
};

struct addr_range {
	const char *start_sym, *end_sym;
	unsigned long long start, end;
};

static unsigned long long _text;
static unsigned long long relative_base;
static struct addr_range text_ranges[] = {
	{ "_stext",     "_etext"     },
	{ "_sinittext", "_einittext" },
};
#define text_range_text     (&text_ranges[0])
#define text_range_inittext (&text_ranges[1])

static struct addr_range percpu_range = {
	"__per_cpu_start", "__per_cpu_end", -1ULL, 0
};

static struct sym_entry **table;
static unsigned int table_size, table_cnt;
static int all_symbols;
static int absolute_percpu;
static int base_relative;

static int token_profit[0x10000];

/* the table that holds the result of the compression */
static unsigned char best_table[256][2];
static unsigned char best_table_len[256];

#ifdef CONFIG_KALLMODSYMS
/*
 * The builtin module names.  The "offset" points to the name as if
 * all builtin module names were concatenated to a single string.
 */
static unsigned int builtin_module_size;	/* number allocated */
static unsigned int builtin_module_len;		/* number assigned */
static char **builtin_modules;			/* array of module names */
static unsigned int *builtin_module_offsets;	/* offset */

/*
 * An ordered list of address ranges and how they map to built-in modules.
 */
struct addrmap_entry {
	unsigned long long addr;
	unsigned long long size;
	unsigned int module;
};
static struct addrmap_entry *addrmap;
static int addrmap_num, addrmap_alloced;
#endif

static void usage(void)
{
	fprintf(stderr, "Usage: kallsyms [--all-symbols] "
			"[--base-relative] [--builtin=modules_thick.builtin] "
			"< in.map > out.S\n");
	exit(1);
}

static char *sym_name(const struct sym_entry *s)
{
	return (char *)s->sym + 1;
}

static bool is_ignored_symbol(const char *name, char type)
{
	static const char * const ignored_symbols[] = {
		/*
		 * Symbols which vary between passes. Passes 1 and 2 must have
		 * identical symbol lists. The kallsyms_* symbols below are
		 * only added after pass 1, they would be included in pass 2
		 * when --all-symbols is specified so exclude them to get a
		 * stable symbol list.
		 */
		"kallsyms_addresses",
		"kallsyms_offsets",
		"kallsyms_relative_base",
		"kallsyms_num_syms",
		"kallsyms_names",
		"kallsyms_markers",
		"kallsyms_token_table",
		"kallsyms_token_index",
		"kallsyms_symbol_modules",
		"kallsyms_modules",
		/* Exclude linker generated symbols which vary between passes */
		"_SDA_BASE_",		/* ppc */
		"_SDA2_BASE_",		/* ppc */
		NULL
	};

	static const char * const ignored_prefixes[] = {
		"$",			/* local symbols for ARM, MIPS, etc. */
		".LASANPC",		/* s390 kasan local symbols */
		"__crc_",		/* modversions */
		"__efistub_",		/* arm64 EFI stub namespace */
		NULL
	};

	static const char * const ignored_suffixes[] = {
		"_from_arm",		/* arm */
		"_from_thumb",		/* arm */
		"_veneer",		/* arm */
		NULL
	};

	const char * const *p;

	/* Exclude symbols which vary between passes. */
	for (p = ignored_symbols; *p; p++)
		if (!strcmp(name, *p))
			return true;

	for (p = ignored_prefixes; *p; p++)
		if (!strncmp(name, *p, strlen(*p)))
			return true;

	for (p = ignored_suffixes; *p; p++) {
		int l = strlen(name) - strlen(*p);

		if (l >= 0 && !strcmp(name + l, *p))
			return true;
	}

	if (type == 'U' || type == 'u')
		return true;
	/* exclude debugging symbols */
	if (type == 'N' || type == 'n')
		return true;

	if (toupper(type) == 'A') {
		/* Keep these useful absolute symbols */
		if (strcmp(name, "__kernel_syscall_via_break") &&
		    strcmp(name, "__kernel_syscall_via_epc") &&
		    strcmp(name, "__kernel_sigtramp") &&
		    strcmp(name, "__gp"))
			return true;
	}

	return false;
}

static void check_symbol_range(const char *sym, unsigned long long addr,
			       struct addr_range *ranges, int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (strcmp(sym, ar->start_sym) == 0) {
			ar->start = addr;
			return;
		} else if (strcmp(sym, ar->end_sym) == 0) {
			ar->end = addr;
			return;
		}
	}
}

#ifdef CONFIG_KALLMODSYMS
static int addrmap_compare(const void *keyp, const void *rangep)
{
	unsigned long long addr = *((const unsigned long long *)keyp);
	const struct addrmap_entry *range = (const struct addrmap_entry *)rangep;

	if (addr < range->addr)
		return -1;
	if (addr < range->addr + range->size)
		return 0;
	return 1;
}
#endif

static struct sym_entry *read_symbol(FILE *in)
{
	char name[500], type;
	unsigned long long addr;
	unsigned int len;
	struct sym_entry *sym;
	int rc;
#ifdef CONFIG_KALLMODSYMS
        unsigned long long size;
	struct addrmap_entry *range;
        unsigned int module;
#endif

        rc = fscanf(in, "%llx %llx %c %499s\n", &addr, &size, &type, name);
	if (rc != 4) {
		if (rc != EOF && fgets(name, 500, in) == NULL)
			fprintf(stderr, "Read error or end of file.\n");
		return NULL;
	}
	if (strlen(name) >= KSYM_NAME_LEN) {
		fprintf(stderr, "Symbol %s too long for kallsyms (%zu >= %d).\n"
				"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c\n",
			name, strlen(name), KSYM_NAME_LEN);
		return NULL;
	}

	if (strcmp(name, "_text") == 0)
		_text = addr;

	/* Ignore most absolute/undefined (?) symbols. */
	if (is_ignored_symbol(name, type))
		return NULL;

	check_symbol_range(name, addr, text_ranges, ARRAY_SIZE(text_ranges));
	check_symbol_range(name, addr, &percpu_range, 1);

#ifdef CONFIG_KALLMODSYMS
	/* look up the builtin module this is part of (if any) */
	range = (struct addrmap_entry *) bsearch(&addr,
	    addrmap, addrmap_num, sizeof(*addrmap), &addrmap_compare);
	if (range)
		module = builtin_module_offsets[range->module];
	else
		module = 0;
#endif

	/* include the type field in the symbol name, so that it gets
	 * compressed together */

	len = strlen(name) + 1;

	sym = malloc(sizeof(*sym) + len + 1);
	if (!sym) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required amount of memory\n");
		exit(EXIT_FAILURE);
	}
	sym->addr = addr;
	sym->len = len;
	sym->sym[0] = type;
	strcpy(sym_name(sym), name);
	sym->percpu_absolute = 0;
        sym->size = size;
#ifdef CONFIG_KALLMODSYMS
        sym->module = module;
#endif

	return sym;
}

static int symbol_in_range(const struct sym_entry *s,
			   const struct addr_range *ranges, int entries)
{
	size_t i;
	const struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (s->addr >= ar->start && s->addr <= ar->end)
			return 1;
	}

	return 0;
}

static int symbol_valid(const struct sym_entry *s)
{
	const char *name = sym_name(s);

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		if (symbol_in_range(s, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext; they can move between pass 1 and 2 when
		 * the kallsyms data are added.  If these symbols move then
		 * they may get dropped in pass 2, which breaks the kallsyms
		 * rules.
		 */
		if ((s->addr == text_range_text->end &&
		     strcmp(name, text_range_text->end_sym)) ||
		    (s->addr == text_range_inittext->end &&
		     strcmp(name, text_range_inittext->end_sym)))
			return 0;
	}

	return 1;
}

/* remove all the invalid symbols from the table */
static void shrink_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if (symbol_valid(table[i])) {
			if (pos != i)
				table[pos] = table[i];
			pos++;
		} else {
			free(table[i]);
		}
	}
	table_cnt = pos;

	/* When valid symbol is not registered, exit to error */
	if (!table_cnt) {
		fprintf(stderr, "No valid symbol.\n");
		exit(1);
	}
}

static void read_map(FILE *in)
{
	struct sym_entry *sym;

	while (!feof(in)) {
		sym = read_symbol(in);
		if (!sym)
			continue;

		sym->start_pos = table_cnt;

		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit (1);
			}
		}

		table[table_cnt++] = sym;
	}
}

static void output_label(const char *label)
{
	printf(".globl %s\n", label);
	printf("\tALGN\n");
	printf("%s:\n", label);
}

/* Provide proper symbols relocatability by their '_text' relativeness. */
static void output_address(unsigned long long addr)
{
	if (_text <= addr)
		printf("\tPTR\t_text + %#llx\n", addr - _text);
	else
		printf("\tPTR\t_text - %#llx\n", _text - addr);
}

/* uncompress a compressed symbol. When this function is called, the best table
 * might still be compressed itself, so the function needs to be recursive */
static int expand_symbol(const unsigned char *data, int len, char *result)
{
	int c, rlen, total=0;

	while (len) {
		c = *data;
		/* if the table holds a single char that is the same as the one
		 * we are looking for, then end the search */
		if (best_table[c][0]==c && best_table_len[c]==1) {
			*result++ = c;
			total++;
		} else {
			/* if not, recurse and expand */
			rlen = expand_symbol(best_table[c], best_table_len[c], result);
			total += rlen;
			result += rlen;
		}
		data++;
		len--;
	}
	*result=0;

	return total;
}

static int symbol_absolute(const struct sym_entry *s)
{
	return s->percpu_absolute;
}

static void write_src(void)
{
	unsigned int i, k, off;
	unsigned int best_idx[256];
	unsigned int *markers;
	char buf[KSYM_NAME_LEN];

	printf("#include <asm/bitsperlong.h>\n");
	printf("#if BITS_PER_LONG == 64\n");
	printf("#define PTR .quad\n");
	printf("#define ALGN .balign 8\n");
	printf("#else\n");
	printf("#define PTR .long\n");
	printf("#define ALGN .balign 4\n");
	printf("#endif\n");

	printf("\t.section .rodata, \"a\"\n");

	if (!base_relative)
		output_label("kallsyms_addresses");
	else
		output_label("kallsyms_offsets");

	for (i = 0; i < table_cnt; i++) {
		if (base_relative) {
			/*
			 * Use the offset relative to the lowest value
			 * encountered of all relative symbols, and emit
			 * non-relocatable fixed offsets that will be fixed
			 * up at runtime.
			 */

			long long offset;
			int overflow;

			if (!absolute_percpu) {
				offset = table[i]->addr - relative_base;
				overflow = (offset < 0 || offset > UINT_MAX);
			} else if (symbol_absolute(table[i])) {
				offset = table[i]->addr;
				overflow = (offset < 0 || offset > INT_MAX);
			} else {
				offset = relative_base - table[i]->addr - 1;
				overflow = (offset < INT_MIN || offset >= 0);
			}
			if (overflow) {
				fprintf(stderr, "kallsyms failure: "
					"%s symbol value %#llx out of range in relative mode\n",
					symbol_absolute(table[i]) ? "absolute" : "relative",
					table[i]->addr);
				exit(EXIT_FAILURE);
			}
			printf("\t.long\t%#x\n", (int)offset);
		} else if (!symbol_absolute(table[i])) {
			output_address(table[i]->addr);
		} else {
			printf("\tPTR\t%#llx\n", table[i]->addr);
		}
	}
	printf("\n");

	if (base_relative) {
		output_label("kallsyms_relative_base");
		output_address(relative_base);
		printf("\n");
	}

	output_label("kallsyms_sizes");
	for (i = 0; i < table_cnt; i++)
		printf("\tPTR\t%#llx\n", table[i]->size);
	printf("\n");

	output_label("kallsyms_num_syms");
	printf("\t.long\t%u\n", table_cnt);
	printf("\n");

	/* table of offset markers, that give the offset in the compressed stream
	 * every 256 symbols */
	markers = malloc(sizeof(unsigned int) * ((table_cnt + 255) / 256));
	if (!markers) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required memory\n");
		exit(EXIT_FAILURE);
	}

	output_label("kallsyms_names");
	off = 0;
	for (i = 0; i < table_cnt; i++) {
		if ((i & 0xFF) == 0)
			markers[i >> 8] = off;

		printf("\t.byte 0x%02x", table[i]->len);
		for (k = 0; k < table[i]->len; k++)
			printf(", 0x%02x", table[i]->sym[k]);
		printf("\n");

		off += table[i]->len + 1;
	}
	printf("\n");

	output_label("kallsyms_markers");
	for (i = 0; i < ((table_cnt + 255) >> 8); i++)
		printf("\t.long\t%u\n", markers[i]);
	printf("\n");

	free(markers);

	output_label("kallsyms_token_table");
	off = 0;
	for (i = 0; i < 256; i++) {
		best_idx[i] = off;
		expand_symbol(best_table[i], best_table_len[i], buf);
		printf("\t.asciz\t\"%s\"\n", buf);
		off += strlen(buf) + 1;
	}
	printf("\n");

	output_label("kallsyms_token_index");
	for (i = 0; i < 256; i++)
		printf("\t.short\t%d\n", best_idx[i]);
	printf("\n");

#ifdef CONFIG_KALLMODSYMS
	output_label("kallsyms_modules");
	for (i = 0; i < builtin_module_len; i++)
		printf("\t.asciz\t\"%s\"\n", builtin_modules[i]);
	printf("\n");

	for (i = 0; i < builtin_module_len; i++)
		free(builtin_modules[i]);

	output_label("kallsyms_symbol_modules");
	for (i = 0; i < table_cnt; i++)
		printf("\t.int\t%d\n", table[i]->module);
	printf("\n");
#endif
}

/* table lookup compression functions */

/* count all the possible tokens in a symbol */
static void learn_symbol(const unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]++;
}

/* decrease the count for all the possible tokens in a symbol */
static void forget_symbol(const unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]--;
}

/* do the initial token count */
static void build_initial_tok_table(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		learn_symbol(table[i]->sym, table[i]->len);
}

static unsigned char *find_token(unsigned char *str, int len,
				 const unsigned char *token)
{
	int i;

	for (i = 0; i < len - 1; i++) {
		if (str[i] == token[0] && str[i+1] == token[1])
			return &str[i];
	}
	return NULL;
}

/* replace a given token in all the valid symbols. Use the sampled symbols
 * to update the counts */
static void compress_symbols(const unsigned char *str, int idx)
{
	unsigned int i, len, size;
	unsigned char *p1, *p2;

	for (i = 0; i < table_cnt; i++) {

		len = table[i]->len;
		p1 = table[i]->sym;

		/* find the token on the symbol */
		p2 = find_token(p1, len, str);
		if (!p2) continue;

		/* decrease the counts for this symbol's tokens */
		forget_symbol(table[i]->sym, len);

		size = len;

		do {
			*p2 = idx;
			p2++;
			size -= (p2 - p1);
			memmove(p2, p2 + 1, size);
			p1 = p2;
			len--;

			if (size < 2) break;

			/* find the token on the symbol */
			p2 = find_token(p1, size, str);

		} while (p2);

		table[i]->len = len;

		/* increase the counts for this symbol's new tokens */
		learn_symbol(table[i]->sym, len);
	}
}

/* search the token with the maximum profit */
static int find_best_token(void)
{
	int i, best, bestprofit;

	bestprofit=-10000;
	best = 0;

	for (i = 0; i < 0x10000; i++) {
		if (token_profit[i] > bestprofit) {
			best = i;
			bestprofit = token_profit[i];
		}
	}
	return best;
}

/* this is the core of the algorithm: calculate the "best" table */
static void optimize_result(void)
{
	int i, best;

	/* using the '\0' symbol last allows compress_symbols to use standard
	 * fast string functions */
	for (i = 255; i >= 0; i--) {

		/* if this table slot is empty (it is not used by an actual
		 * original char code */
		if (!best_table_len[i]) {

			/* find the token with the best profit value */
			best = find_best_token();
			if (token_profit[best] == 0)
				break;

			/* place it in the "best" table */
			best_table_len[i] = 2;
			best_table[i][0] = best & 0xFF;
			best_table[i][1] = (best >> 8) & 0xFF;

			/* replace this token in all the valid symbols */
			compress_symbols(best_table[i], i);
		}
	}
}

/* start by placing the symbols that are actually used on the table */
static void insert_real_symbols_in_table(void)
{
	unsigned int i, j, c;

	for (i = 0; i < table_cnt; i++) {
		for (j = 0; j < table[i]->len; j++) {
			c = table[i]->sym[j];
			best_table[c][0]=c;
			best_table_len[c]=1;
		}
	}
}

static void optimize_token_table(void)
{
	build_initial_tok_table();

	insert_real_symbols_in_table();

	optimize_result();
}

/* guess for "linker script provide" symbol */
static int may_be_linker_script_provide_symbol(const struct sym_entry *se)
{
	const char *symbol = sym_name(se);
	int len = se->len - 1;

	if (len < 8)
		return 0;

	if (symbol[0] != '_' || symbol[1] != '_')
		return 0;

	/* __start_XXXXX */
	if (!memcmp(symbol + 2, "start_", 6))
		return 1;

	/* __stop_XXXXX */
	if (!memcmp(symbol + 2, "stop_", 5))
		return 1;

	/* __end_XXXXX */
	if (!memcmp(symbol + 2, "end_", 4))
		return 1;

	/* __XXXXX_start */
	if (!memcmp(symbol + len - 6, "_start", 6))
		return 1;

	/* __XXXXX_end */
	if (!memcmp(symbol + len - 4, "_end", 4))
		return 1;

	return 0;
}

static int compare_symbols(const void *a, const void *b)
{
	const struct sym_entry *sa = *(const struct sym_entry **)a;
	const struct sym_entry *sb = *(const struct sym_entry **)b;
	int wa, wb;

	/* sort by address first */
	if (sa->addr > sb->addr)
		return 1;
	if (sa->addr < sb->addr)
		return -1;

	/* zero-size markers before nonzero-size symbols */
	if (sa->size > 0 && sb->size == 0)
		return 1;
	if (sa->size == 0 && sb->size > 0)
		return -1;

	/* sort by size (large size preceding symbols it encompasses) */
	if (sa->size < sb->size)
		return 1;
	if (sa->size > sb->size)
		return -1;

	/* sort by "weakness" type */
	wa = (sa->sym[0] == 'w') || (sa->sym[0] == 'W');
	wb = (sb->sym[0] == 'w') || (sb->sym[0] == 'W');
	if (wa != wb)
		return wa - wb;

	/* sort by "linker script provide" type */
	wa = may_be_linker_script_provide_symbol(sa);
	wb = may_be_linker_script_provide_symbol(sb);
	if (wa != wb)
		return wa - wb;

	/* sort by the number of prefix underscores */
	wa = strspn(sym_name(sa), "_");
	wb = strspn(sym_name(sb), "_");
	if (wa != wb)
		return wa - wb;

	/* sort by initial order, so that other symbols are left undisturbed */
	return sa->start_pos - sb->start_pos;
}

static void sort_symbols(void)
{
	qsort(table, table_cnt, sizeof(table[0]), compare_symbols);
}

static void make_percpus_absolute(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (symbol_in_range(table[i], &percpu_range, 1)) {
			/*
			 * Keep the 'A' override for percpu symbols to
			 * ensure consistent behavior compared to older
			 * versions of this tool.
			 */
			table[i]->sym[0] = 'A';
			table[i]->percpu_absolute = 1;
		}
}

/* find the minimum non-absolute symbol address */
static void record_relative_base(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (!symbol_absolute(table[i])) {
			/*
			 * The table is sorted by address.
			 * Take the first non-absolute symbol value.
			 */
			relative_base = table[i]->addr;
			return;
		}
}

#ifdef CONFIG_KALLMODSYMS
/* Built-in module list computation. */

/*
 * Expand the builtin modules list.
 */
static void expand_builtin_modules(void)
{
	builtin_module_size += 50;

	builtin_modules = realloc(builtin_modules,
				  sizeof(*builtin_modules) *
				  builtin_module_size);
	builtin_module_offsets = realloc(builtin_module_offsets,
					 sizeof(*builtin_module_offsets) *
					 builtin_module_size);

	if (!builtin_modules || !builtin_module_offsets) {
		fprintf(stderr, "kallsyms failure: out of memory.\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Add a single built-in module (possibly composed of many files) to the
 * modules list.  Take the offset of the current module and return it
 * (purely for simplicity's sake in the caller).
 */
static size_t add_builtin_module(const char *module_name, char **module_paths,
				 GHashTable *obj2mod, size_t offset)
{
	gpointer val = GUINT_TO_POINTER(builtin_module_len);

	/* map the module's object paths to the module offset */
	while (*module_paths) {
		g_hash_table_insert(obj2mod, strdup(*module_paths), val);
		module_paths++;
	}

	/* add the module name */
	if (builtin_module_size <= builtin_module_len)
		expand_builtin_modules();
	builtin_modules[builtin_module_len] = strdup(module_name);
	builtin_module_offsets[builtin_module_len] = offset;
	builtin_module_len++;

	return (offset + strlen(module_name) + 1);
}

/*
 * Read the linker map.
 */
static void read_linker_map(GHashTable *obj2mod)
{
	unsigned long long addr, size;
	char obj[PATH_MAX+1];
	FILE *f = fopen(".tmp_vmlinux.ranges", "r");

	if (!f) {
		fprintf(stderr, "Cannot open '.tmp_vmlinux.ranges'.\n");
		exit(1);
	}

	addrmap_num = 0;
	addrmap_alloced = 4096;
	addrmap = malloc(sizeof(*addrmap) * addrmap_alloced);
	if (!addrmap)
		goto oom;

	/*
	 * For each address range (addr,size) and object, add to addrmap
	 * the range and the built-in module to which the object maps.
	 */
	while (fscanf(f, "%llx %llx %s\n", &addr, &size, obj) == 3) {
		int m = GPOINTER_TO_UINT(g_hash_table_lookup(obj2mod, obj));

		if (addr == 0 || size == 0 || m == 0)
			continue;

		if (addrmap_num >= addrmap_alloced) {
			addrmap_alloced *= 2;
			addrmap = realloc(addrmap,
			    sizeof(*addrmap) * addrmap_alloced);
			if (!addrmap)
				goto oom;
		}

		addrmap[addrmap_num].addr = addr;
		addrmap[addrmap_num].size = size;
		addrmap[addrmap_num].module = m;
		addrmap_num++;
	}
	fclose(f);
	return;

oom:
	fprintf(stderr, "kallsyms: out of memory\n");
	exit(1);
}

/*
 * Read the list of built-in modules.  Construct:
 *   - builtin_modules: array of module names
 *   - builtin_module_offsets: array of offsets to find module names
 *   - obj2mod: mapping from each object-file path to a module index
 *       (which can be used in the arrays)
 * Finally, read the linker map.
 */
static void read_modules(const char *modules_builtin)
{
	struct modules_thick_iter *i;
	size_t offset = 0;
	char *module_name = NULL;
	char **module_paths;
	GHashTable *obj2mod;

	obj2mod = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	if (!obj2mod) {
		fprintf(stderr, "kallsyms: out of memory\n");
		exit(1);
	}

	/*
	 * builtin_modules[0] is a null entry signifying a symbol that cannot be
	 * modular.
	 */
	builtin_module_size = 50;
	builtin_modules = malloc(sizeof(*builtin_modules) *
				 builtin_module_size);
	builtin_module_offsets = malloc(sizeof(*builtin_module_offsets) *
				 builtin_module_size);
	if (!builtin_modules || !builtin_module_offsets) {
		fprintf(stderr, "kallsyms: out of memory\n");
		exit(1);
	}
	builtin_modules[0] = strdup("");
	builtin_module_offsets[0] = 0;
	builtin_module_len = 1;
	offset++;

	/*
	 * Iterate over all modules in modules_thick.builtin and add each.
	 */
	i = modules_thick_iter_new(modules_builtin);
	if (i == NULL) {
		fprintf(stderr, "Cannot iterate over builtin modules.\n");
		exit(1);
	}

	while ((module_paths = modules_thick_iter_next(i, &module_name)) != NULL) {
		offset = add_builtin_module(module_name, module_paths,
					    obj2mod, offset);
		free(module_paths);
		module_paths = NULL;
	}

	free(module_name);
	modules_thick_iter_free(i);

	/*
	 * Read linker map.
	 */
	read_linker_map(obj2mod);

	g_hash_table_destroy(obj2mod);
}
#else
static void read_modules(const char *unused) {}
#endif /* CONFIG_KALLMODSYMS */

int main(int argc, char **argv)
{
	const char *modules_builtin = "modules_thick.builtin";

	if (argc >= 1) {
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--all-symbols") == 0)
				all_symbols = 1;
			else if (strcmp(argv[i], "--absolute-percpu") == 0)
				absolute_percpu = 1;
			else if (strcmp(argv[i], "--base-relative") == 0)
				base_relative = 1;
			else if (strncmp(argv[i], "--builtin=", 10) == 0)
				modules_builtin = &argv[i][10];
			else
				usage();
		}
	} else if (argc != 1)
		usage();

	read_modules(modules_builtin);
	read_map(stdin);
	shrink_table();
	if (absolute_percpu)
		make_percpus_absolute();
	sort_symbols();
	if (base_relative)
		record_relative_base();
	optimize_token_table();
	write_src();

	return 0;
}
