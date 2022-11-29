/* SPDX-License-Identifier: GPL-2.0 */

/* Used only by link-vmlinux.sh */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main (void)
{
	int i = 0;
	while (!feof(stdin)) {
		uint64_t a, b;
		int ret;
		char *rest = NULL;

		i++;
		if ((ret = scanf("%" SCNx64 " %" SCNx64 " %m[^\n]\n", &a, &b, &rest)) < 3) {
			fprintf(stderr,
				"Syntax error: invalid line %i found in rangefile generation: at least three fields expected, %i converted\n", i, ret);
			exit(1);
		}

		printf("0x%018" PRIx64 " %s\n", a+b, rest);
		free(rest);
	}
	exit(0);
}
