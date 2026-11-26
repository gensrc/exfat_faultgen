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

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

static int	find_allocated_cluster(struct faultgen_ctx *ctx,
		    uint32_t *cnp);

/*
 * Locate a valid in-use cluster (defaulting to the root directory cluster).
 */
static int
find_allocated_cluster(struct faultgen_ctx *ctx, uint32_t *cnp)
{
	int error;

	if (ctx == NULL || cnp == NULL)
		return (EINVAL);

	if (exfat_cluster_is_valid(ctx->root_dir_cluster, ctx->cluster_count)) {
		*cnp = ctx->root_dir_cluster;
		return (0);
	}

	for (uint32_t c = EXFAT_FIRST_CLUSTER;
	    EXFAT_CNTOI(c) < ctx->cluster_count; c++) {
		uint32_t val;

		error = fat_get(ctx, c, &val);
		if (error == 0 && val != EXFAT_FAT_FREE) {
			*cnp = c;
			return (0);
		}
	}

	return (ENOENT);
}

/*
 * Create a circular cluster cycle in FAT chain (Spec §4.1.3).
 */
int
fault_fat_cycle(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t c1, c2;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		char *endp;

		if (parse_u32_str(arg, &endp, &c1) != 0)
			return (EINVAL);
		if (*endp == ',') {
			if (parse_u32_str(endp + 1, NULL, &c2) != 0)
				return (EINVAL);
		} else if (*endp == '\0')
			c2 = c1;
		else
			return (EINVAL);
		if (!exfat_cluster_is_valid(c1, ctx->cluster_count) ||
		    !exfat_cluster_is_valid(c2, ctx->cluster_count))
			return (EINVAL);
	} else {
		error = find_allocated_cluster(ctx, &c1);
		if (error != 0)
			return (error);
		c2 = c1;
	}

	error = fat_set_all(ctx, c1, c2);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Resolve a target cluster from an optional CLI argument, falling back to
 * the first allocated cluster in the active FAT.
 */
static int
resolve_target_cluster(struct faultgen_ctx *ctx, const char *arg,
    uint32_t *cnp)
{
	if (arg != NULL && *arg != '\0') {
		if (parse_u32_str(arg, NULL, cnp) != 0 ||
		    !exfat_cluster_is_valid(*cnp, ctx->cluster_count))
			return (EINVAL);
		return (0);
	}
	return (find_allocated_cluster(ctx, cnp));
}

/*
 * Mark an allocated cluster as EXFAT_FAT_BAD in FAT (Spec §4.1.3).
 */
int
fault_fat_bad_cluster(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t cn;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = resolve_target_cluster(ctx, arg, &cn);
	if (error != 0)
		return (error);

	error = fat_set_all(ctx, cn, EXFAT_FAT_BAD);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Cross-link cluster chain into another file's chain (Spec §4.1.3).
 */
int
fault_fat_crosslink(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t src, dst;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		char *endp;

		if (parse_u32_str(arg, &endp, &src) != 0 || *endp != ',')
			return (EINVAL);
		if (parse_u32_str(endp + 1, NULL, &dst) != 0)
			return (EINVAL);
		if (!exfat_cluster_is_valid(src, ctx->cluster_count) ||
		    !exfat_cluster_is_valid(dst, ctx->cluster_count) ||
		    src == dst)
			return (EINVAL);
	} else {
		if (ctx->cluster_count < 2)
			return (ENOSPC);
		error = find_allocated_cluster(ctx, &dst);
		if (error != 0)
			return (error);
		src = (dst == EXFAT_FIRST_CLUSTER) ?
		    (dst + 1) : EXFAT_FIRST_CLUSTER;
	}

	error = fat_set_all(ctx, src, dst);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Point FAT entry beyond volume cluster heap range (Spec §4.1.3).
 */
int
fault_fat_out_of_bounds(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t cn, target;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (EXFAT_ITOCN((uint64_t)ctx->cluster_count) >= EXFAT_FAT_BAD)
		target = EXFAT_FAT_RESERVED;
	else
		target = EXFAT_ITOCN(ctx->cluster_count);

	if (arg != NULL && *arg != '\0') {
		char *endp;

		if (parse_u32_str(arg, &endp, &cn) != 0)
			return (EINVAL);
		if (*endp == ',') {
			if (parse_u32_str(endp + 1, NULL, &target) != 0)
				return (EINVAL);
			if (target != EXFAT_FAT_RESERVED &&
			    (target < EXFAT_ITOCN(ctx->cluster_count) ||
			    EXFAT_FAT_IS_BAD(target) ||
			    EXFAT_FAT_IS_EOF(target)))
				return (EINVAL);
		} else if (*endp != '\0')
			return (EINVAL);
		if (!exfat_cluster_is_valid(cn, ctx->cluster_count))
			return (EINVAL);
	} else {
		error = find_allocated_cluster(ctx, &cn);
		if (error != 0)
			return (error);
	}

	error = fat_set_all(ctx, cn, target);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Mutate secondary FAT to diverge from active FAT (Spec §3.1.13.1, §4.1).
 */
int
fault_fat_mirror_diverge(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t cn, cur_val, new_val;
	uint8_t active_fat, inactive_fat;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	/*
	 * Spec §3.1.13.1 and §4.1: Mirror divergence requires TexFAT with
	 * two File Allocation Tables (NumberOfFats == 2).
	 */
	if (ctx->num_fats < 2)
		return (ENOTSUP);

	active_fat = exfat_active_fat(ctx);
	inactive_fat = (active_fat == 0) ? 1 : 0;

	error = resolve_target_cluster(ctx, arg, &cn);
	if (error != 0)
		return (error);

	error = fat_get_entry(ctx, active_fat, cn, &cur_val);
	if (error != 0)
		return (error);

	if (cur_val == EXFAT_FAT_FREE)
		new_val = EXFAT_FAT_EOF;
	else
		new_val = EXFAT_FAT_FREE;

	error = fat_set_entry(ctx, inactive_fat, cn, new_val);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}
