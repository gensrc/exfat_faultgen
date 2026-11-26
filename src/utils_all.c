/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "faultgen.h"
#include "subr.h"

static void	print_section_header(const char *num, const char *title);

/*
 * Print a standardized section header banner.
 */
static void
print_section_header(const char *num, const char *title)
{
	print_divider('=');
	printf(" [%s] %s\n", num, title);
	print_divider('=');
}

/*
 * Perform a comprehensive volume audit, sequentially invoking each
 * subsystem inspection utility (Spec §3, §4, §7).
 */
int
util_dump_all(struct faultgen_ctx *ctx, const char *arg)
{
	static const struct {
		const char	*num;
		const char	*title;
		const char	*label;
		int		(*fn)(struct faultgen_ctx *, const char *);
	} sections[] = {
		{ "1/4", "Boot Region & Volume Parameters (Spec §3)",
		    "Boot", util_dump_boot },
		{ "2/4", "File Allocation Table (FAT) (Spec §4)",
		    "FAT", util_dump_fat },
		{ "3/4", "Allocation Bitmap (Spec §7.1)",
		    "Bitmap", util_dump_bitmap },
		{ "4/4", "Directory Hierarchy & Entry Sets (Spec §6, §7)",
		    "Directory", util_dump_dentries },
	};
	int error, first_error;

	(void)arg;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (ctx->json)
		return (util_verify(ctx, arg));

	first_error = 0;

	print_divider('=');
	printf("               exFAT Volume Comprehensive Audit Report\n");
	print_divider('=');
	printf("\n");

	for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
		if (i > 0)
			printf("\n");
		print_section_header(sections[i].num, sections[i].title);
		error = sections[i].fn(ctx, NULL);
		if (error != 0) {
			warnx("[%s] %s dump encountered error: %s",
			    sections[i].num, sections[i].label,
			    strerror(error));
			if (first_error == 0)
				first_error = error;
		}
	}

	printf("\n");
	print_divider('=');
	printf("                    End of Comprehensive Report\n");
	print_divider('=');

	return (first_error);
}
