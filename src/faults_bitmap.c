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

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

/*
 * Set or clear cluster cn in both active and (if dual-FAT) secondary
 * Allocation Bitmaps, then sync the image.
 */
static int
bitmap_set_bit_all(struct faultgen_ctx *ctx, const struct bitmap_info *info,
    uint32_t cn, bool val)
{
	int error;

	error = bitmap_set_bit(ctx, info, cn, val);
	if (error != 0)
		return (error);

	if (ctx->num_fats == 2) {
		struct bitmap_info sec_info;
		bool active_is_second;

		active_is_second = (exfat_active_fat(ctx) == 1);
		if (bitmap_find_secondary_entry(ctx, !active_is_second,
		    &sec_info) == 0) {
			error = bitmap_set_bit(ctx, &sec_info, cn, val);
			if (error != 0)
				return (error);
		}
	}

	return (sync_image(ctx));
}

/*
 * Update bm_data_length in an Allocation Bitmap root directory entry.
 */
static int
bitmap_set_dentry_length(struct faultgen_ctx *ctx,
    const struct bitmap_info *info, uint64_t new_len)
{
	uint8_t *cbuf;
	union exfat_dentry *dent;
	int error;

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, info->dentry_cluster, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	dent = (union exfat_dentry *)(cbuf + info->dentry_offset);
	dent->bitmap.bm_data_length = htole64(new_len);

	error = write_cluster(ctx, info->dentry_cluster, cbuf);
	free(cbuf);
	return (error);
}

/*
 * Mark unreferenced cluster allocated in allocation bitmap (Spec §7.1).
 */
int
fault_bitmap_orphan(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint32_t cn;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = bitmap_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		if (parse_u32_str(arg, NULL, &cn) != 0 ||
		    !exfat_cluster_is_valid(cn, ctx->cluster_count))
			return (EINVAL);
	} else {
		/* Search for the first unallocated cluster in bitmap */
		bool found = false;

		for (uint32_t c = EXFAT_FIRST_CLUSTER;
		    EXFAT_CNTOI(c) < ctx->cluster_count; c++) {
			bool is_set;

			error = bitmap_get_bit(ctx, &info, c, &is_set);
			if (error == 0 && !is_set) {
				cn = c;
				found = true;
				break;
			}
		}
		if (!found)
			return (ENOSPC);
	}

	return (bitmap_set_bit_all(ctx, &info, cn, true));
}

/*
 * Clear bitmap allocation bit for an in-use cluster (Spec §7.1).
 */
int
fault_bitmap_false_free(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint32_t cn;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = bitmap_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		if (parse_u32_str(arg, NULL, &cn) != 0 ||
		    !exfat_cluster_is_valid(cn, ctx->cluster_count))
			return (EINVAL);
	} else {
		/*
		 * Find an allocated cluster to mark free. Search starting from
		 * root dir cluster to find an in-use cluster.
		 */
		bool found = false;

		for (uint32_t c = ctx->root_dir_cluster;
		    EXFAT_CNTOI(c) < ctx->cluster_count; c++) {
			bool is_set;

			error = bitmap_get_bit(ctx, &info, c, &is_set);
			if (error == 0 && is_set) {
				cn = c;
				found = true;
				break;
			}
		}
		if (!found) {
			for (uint32_t c = EXFAT_FIRST_CLUSTER;
			    c < ctx->root_dir_cluster &&
			    EXFAT_CNTOI(c) < ctx->cluster_count; c++) {
				bool is_set;

				error = bitmap_get_bit(ctx, &info, c, &is_set);
				if (error == 0 && is_set) {
					cn = c;
					found = true;
					break;
				}
			}
		}
		if (!found)
			return (ENOENT);
	}

	return (bitmap_set_bit_all(ctx, &info, cn, false));
}

/*
 * Truncate allocation bitmap length in directory entry (Spec §7.1.4).
 */
int
fault_bitmap_truncate(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint64_t min_size, new_len;
	int error;

	(void)arg;
	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = bitmap_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	/*
	 * Truncate bm_data_length so it is less than min_bitmap_size
	 * (howmany(cluster_count, 8)) per Spec §7.1.4.
	 */
	min_size = howmany((uint64_t)ctx->cluster_count, 8);
	new_len = (min_size > 1) ? min_size - 1 : 0;

	error = bitmap_set_dentry_length(ctx, &info, new_len);
	if (error != 0)
		return (error);

	if (ctx->num_fats == 2) {
		struct bitmap_info sec_info;
		bool active_is_second;

		active_is_second = (exfat_active_fat(ctx) == 1);
		if (bitmap_find_secondary_entry(ctx, !active_is_second,
		    &sec_info) == 0) {
			error = bitmap_set_dentry_length(ctx, &sec_info,
			    new_len);
			if (error != 0)
				return (error);
		}
	}

	return (sync_image(ctx));
}

/*
 * Mutate secondary Allocation Bitmap to diverge in dual-FAT
 * (Spec §7.1, §3.1.13.1).
 */
int
fault_bitmap_mirror_diverge(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint32_t cn;
	int error;
	bool active_is_second, cur_val;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (ctx->num_fats < 2)
		return (ENOTSUP);

	active_is_second = (exfat_active_fat(ctx) == 1);

	error = bitmap_find_secondary_entry(ctx, !active_is_second, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		if (parse_u32_str(arg, NULL, &cn) != 0 ||
		    !exfat_cluster_is_valid(cn, ctx->cluster_count))
			return (EINVAL);
	} else
		cn = EXFAT_FIRST_CLUSTER;

	error = bitmap_get_bit(ctx, &info, cn, &cur_val);
	if (error != 0)
		return (error);

	error = bitmap_set_bit(ctx, &info, cn, !cur_val);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Set invalid reserved bits in Allocation Bitmap flags (Spec §7.1.2).
 */
int
fault_bitmap_flags_reserved(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint8_t *cbuf;
	union exfat_dentry *dent;
	uint8_t new_flags;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = bitmap_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) != 0 || val > 255)
			return (EINVAL);
		new_flags = (uint8_t)val;
	} else if (ctx->num_fats == 1) {
		/*
		 * Set Second flag on single-FAT volume and reserved bit 7
		 * (violates Spec §7.1.2).
		 */
		new_flags = EXFAT_BITMAP_FLAG_SECOND | 0x80;
	} else {
		/* Set reserved bits 1..7 (Spec §7.1.2 requires 0) */
		new_flags = 0xFE |
		    (exfat_active_fat(ctx) == 1 ? EXFAT_BITMAP_FLAG_SECOND : 0);
	}

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, info.dentry_cluster, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	dent = (union exfat_dentry *)(cbuf + info.dentry_offset);
	dent->bitmap.bm_flags = new_flags;

	error = write_cluster(ctx, info.dentry_cluster, cbuf);
	free(cbuf);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}
