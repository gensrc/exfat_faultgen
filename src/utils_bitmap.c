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
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

static int	bitmap_find_entry_common(struct faultgen_ctx *ctx,
		    bool target_second, bool single_fat_mask,
		    struct bitmap_info *info);
static int	bitmap_locate_bit(struct faultgen_ctx *ctx,
		    const struct bitmap_info *info, uint32_t cn,
		    uint32_t *target_cn, size_t *offset_out,
		    uint8_t *mask_out);
static void	print_bitmap_run(uint32_t run_start, uint32_t run_len,
		    int run_state);

/*
 * Scan the root directory for an Allocation Bitmap directory entry matching
 * target_second (Spec §7.1).
 */
static int
bitmap_find_entry_common(struct faultgen_ctx *ctx, bool target_second,
    bool single_fat_mask, struct bitmap_info *info)
{
	uint8_t *cbuf;
	uint32_t clusters_visited, curr_cn;
	int error;

	if (ctx == NULL || info == NULL)
		return (EINVAL);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	clusters_visited = 0;
	curr_cn = ctx->root_dir_cluster;

	while (exfat_cluster_is_valid(curr_cn, ctx->cluster_count)) {
		union exfat_dentry *dentries;
		size_t num_dentries;
		uint32_t next_cn;

		error = read_cluster(ctx, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		num_dentries = ctx->cluster_size / sizeof(union exfat_dentry);
		dentries = (union exfat_dentry *)cbuf;

		for (size_t i = 0; i < num_dentries; i++) {
			bool is_second;

			if (dentries[i].type == EXFAT_ENTRY_EOD) {
				free(cbuf);
				return (ENOENT);
			}

			if (dentries[i].type != EXFAT_ENTRY_BITMAP)
				continue;

			is_second = (dentries[i].bitmap.bm_flags &
			    EXFAT_BITMAP_FLAG_SECOND) != 0;
			if (single_fat_mask && ctx->num_fats <= 1)
				is_second = false;
			if (is_second == target_second) {
				info->first_cluster = le32toh(
				    dentries[i].bitmap.bm_first_cluster);
				info->data_length = le64toh(
				    dentries[i].bitmap.bm_data_length);
				info->dentry_cluster = curr_cn;
				info->dentry_offset = i *
				    sizeof(union exfat_dentry);
				info->fat_idx = is_second ? 1 : 0;
				free(cbuf);
				return (0);
			}
		}

		error = fat_get(ctx, curr_cn, &next_cn);
		if (error != 0) {
			free(cbuf);
			return (error);
		}
		if (!exfat_cluster_is_valid(next_cn, ctx->cluster_count) ||
		    ++clusters_visited > ctx->cluster_count)
			break;
		curr_cn = next_cn;
	}

	free(cbuf);
	return (ENOENT);
}

/*
 * Locate the active Allocation Bitmap directory entry in the root directory
 * per Spec §7.1.
 */
int
bitmap_find_entry(struct faultgen_ctx *ctx, struct bitmap_info *info)
{
	return (bitmap_find_entry_common(ctx, exfat_active_fat(ctx) == 1,
	    true, info));
}

/*
 * Locate specific (active or secondary) Allocation Bitmap entry in root
 * directory (Spec §7.1).
 */
int
bitmap_find_secondary_entry(struct faultgen_ctx *ctx, bool target_second,
    struct bitmap_info *info)
{
	return (bitmap_find_entry_common(ctx, target_second, false, info));
}

/*
 * Locate the on-disk cluster, byte offset, and bitmask for a cluster's
 * Allocation Bitmap bit (Spec §7.1).
 */
static int
bitmap_locate_bit(struct faultgen_ctx *ctx, const struct bitmap_info *info,
    uint32_t cn, uint32_t *target_cn, size_t *offset_out, uint8_t *mask_out)
{
	uint32_t cluster_idx, curr_cn;
	size_t byte_idx, cluster_num_in_chain;
	int error;

	if (ctx == NULL || info == NULL ||
	    !exfat_cluster_is_valid(cn, ctx->cluster_count))
		return (EINVAL);

	cluster_idx = EXFAT_CNTOI(cn);
	byte_idx = cluster_idx / 8;
	if (byte_idx >= info->data_length)
		return (EINVAL);

	cluster_num_in_chain = byte_idx / ctx->cluster_size;
	curr_cn = info->first_cluster;
	for (size_t i = 0; i < cluster_num_in_chain; i++) {
		uint32_t next_cn;

		error = fat_get_entry(ctx, info->fat_idx, curr_cn, &next_cn);
		if (error != 0)
			return (error);
		if (!exfat_cluster_is_valid(next_cn, ctx->cluster_count))
			return (EIO);
		curr_cn = next_cn;
	}

	*target_cn = curr_cn;
	*offset_out = byte_idx % ctx->cluster_size;
	*mask_out = 1U << (cluster_idx % 8);
	return (0);
}

/*
 * Read the allocation bitmap bit for a cluster per Spec §7.1.
 */
int
bitmap_get_bit(struct faultgen_ctx *ctx, const struct bitmap_info *info,
    uint32_t cn, bool *val)
{
	uint8_t *cbuf;
	uint32_t curr_cn;
	size_t offset_in_cluster;
	uint8_t bit_mask;
	int error;

	if (val == NULL)
		return (EINVAL);

	error = bitmap_locate_bit(ctx, info, cn, &curr_cn, &offset_in_cluster,
	    &bit_mask);
	if (error != 0)
		return (error);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, curr_cn, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	*val = (cbuf[offset_in_cluster] & bit_mask) != 0;
	free(cbuf);

	return (0);
}

/*
 * Set or clear the allocation bitmap bit for a cluster per Spec §7.1.
 */
int
bitmap_set_bit(struct faultgen_ctx *ctx, const struct bitmap_info *info,
    uint32_t cn, bool val)
{
	uint8_t *cbuf;
	uint32_t curr_cn;
	size_t offset_in_cluster;
	uint8_t bit_mask;
	int error;

	error = bitmap_locate_bit(ctx, info, cn, &curr_cn, &offset_in_cluster,
	    &bit_mask);
	if (error != 0)
		return (error);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, curr_cn, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	if (val)
		cbuf[offset_in_cluster] |= bit_mask;
	else
		cbuf[offset_in_cluster] &= ~bit_mask;

	error = write_cluster(ctx, curr_cn, cbuf);
	free(cbuf);
	return (error);
}

/*
 * Print a contiguous run of clusters with the same allocation state.
 */
static void
print_bitmap_run(uint32_t run_start, uint32_t run_len, int run_state)
{
	const char *state_str;

	switch (run_state) {
	case 1:
		state_str = "ALLOCATED";
		break;
	case 0:
		state_str = "FREE";
		break;
	default:
		state_str = "UNCOVERED";
		break;
	}

	if (run_len == 1)
		printf("  [%" PRIu32 "]: %s (1 cluster)\n", run_start,
		    state_str);
	else
		printf("  [%" PRIu32 " - %" PRIu32 "]: %s (%" PRIu32
		    " clusters)\n", run_start, run_start + run_len - 1,
		    state_str, run_len);
}

/*
 * Perform verification of Allocation Bitmap metadata and consistency
 * (Spec §7.1).
 */
int
bitmap_verify(struct faultgen_ctx *ctx, struct bitmap_verify_stats *stats)
{
	struct bitmap_info info, sec_info;
	struct upcase_info uc_info;
	uint8_t *cbuf, *sbuf;
	uint64_t expected_bytes;
	uint32_t curr_bitmap_cn, curr_cluster_idx;
	uint32_t curr_sec_bitmap_cn;
	int error;
	uint8_t sec_fat_idx;
	bool found_sec, has_sec, has_uc;

	if (ctx == NULL || stats == NULL)
		return (EINVAL);

	memset(&info, 0, sizeof(info));
	memset(&sec_info, 0, sizeof(sec_info));
	memset(&uc_info, 0, sizeof(uc_info));
	memset(stats, 0, sizeof(*stats));

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	has_uc = (upcase_find_entry(ctx, &uc_info) == 0 &&
	    exfat_cluster_is_valid(uc_info.first_cluster, ctx->cluster_count));

	error = bitmap_find_entry(ctx, &info);
	if (error != 0) {
		stats->found = false;
		return (0);
	}

	stats->found = true;
	stats->first_cluster = info.first_cluster;
	stats->data_length = info.data_length;

	expected_bytes = howmany((uint64_t)ctx->cluster_count, 8);
	if (info.data_length < expected_bytes ||
	    info.data_length > EXFAT_MAX_BITMAP_SIZE)
		stats->size_errors++;

	found_sec = false;
	sec_fat_idx = 0;
	if (ctx->num_fats == 2) {
		bool active_is_sec;

		active_is_sec = (exfat_active_fat(ctx) == 1);
		sec_fat_idx = active_is_sec ? 0 : 1;
		found_sec = (bitmap_find_secondary_entry(ctx, !active_is_sec,
		    &sec_info) == 0);
		if (!found_sec)
			stats->found = false;
		else if (sec_info.data_length < expected_bytes ||
		    sec_info.data_length > EXFAT_MAX_BITMAP_SIZE)
			stats->size_errors++;
	}

	if (!exfat_cluster_is_valid(info.first_cluster, ctx->cluster_count)) {
		stats->uncovered = ctx->cluster_count;
		return (0);
	}

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	curr_bitmap_cn = info.first_cluster;
	error = read_cluster(ctx, curr_bitmap_cn, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}
	curr_cluster_idx = 0;

	sbuf = NULL;
	curr_sec_bitmap_cn = 0;
	has_sec = false;

	if (found_sec &&
	    exfat_cluster_is_valid(sec_info.first_cluster,
	    ctx->cluster_count)) {
		sbuf = malloc(ctx->cluster_size);
		if (sbuf != NULL) {
			curr_sec_bitmap_cn = sec_info.first_cluster;
			if (read_cluster(ctx, curr_sec_bitmap_cn, sbuf) == 0)
				has_sec = true;
			else {
				free(sbuf);
				sbuf = NULL;
			}
		}
	}

	for (uint32_t cn = EXFAT_FIRST_CLUSTER;
	    cn < EXFAT_FIRST_CLUSTER + ctx->cluster_count; cn++) {
		size_t byte_idx, offset_in_cluster;
		uint32_t cluster_idx, needed_cluster_idx;
		bool bit_val;

		cluster_idx = EXFAT_CNTOI(cn);
		byte_idx = cluster_idx / 8;

		if (byte_idx >= info.data_length) {
			stats->uncovered++;
			continue;
		}

		needed_cluster_idx = byte_idx / ctx->cluster_size;
		offset_in_cluster = byte_idx % ctx->cluster_size;

		while (curr_cluster_idx < needed_cluster_idx) {
			uint32_t next_cn;

			error = fat_get(ctx, curr_bitmap_cn, &next_cn);
			if (error != 0) {
				free(cbuf);
				free(sbuf);
				return (error);
			}
			if (!exfat_cluster_is_valid(next_cn,
			    ctx->cluster_count)) {
				stats->uncovered += (EXFAT_FIRST_CLUSTER +
				    ctx->cluster_count) - cn;
				free(cbuf);
				free(sbuf);
				return (0);
			}
			curr_bitmap_cn = next_cn;
			error = read_cluster(ctx, curr_bitmap_cn, cbuf);
			if (error != 0) {
				free(cbuf);
				free(sbuf);
				return (error);
			}

			if (has_sec) {
				uint32_t next_sec_cn;

				if (fat_get_entry(ctx, sec_fat_idx,
				    curr_sec_bitmap_cn, &next_sec_cn) == 0 &&
				    exfat_cluster_is_valid(next_sec_cn,
				    ctx->cluster_count) &&
				    read_cluster(ctx, next_sec_cn,
				    sbuf) == 0)
					curr_sec_bitmap_cn = next_sec_cn;
				else
					has_sec = false;
			}

			curr_cluster_idx++;
		}

		bit_val = (cbuf[offset_in_cluster] &
		    (1U << (cluster_idx % 8))) != 0;
		if (bit_val)
			stats->total_alloc++;
		else {
			uint32_t fat_val;

			stats->total_free++;
			if (cn == ctx->root_dir_cluster ||
			    cn == info.first_cluster ||
			    (ctx->num_fats == 2 && stats->found &&
			    cn == sec_info.first_cluster) ||
			    (has_uc && cn == uc_info.first_cluster) ||
			    (fat_get(ctx, cn, &fat_val) == 0 &&
			    fat_val != EXFAT_FAT_FREE))
				stats->sync_errors++;
		}

		if (has_sec) {
			if (byte_idx < sec_info.data_length) {
				bool sec_val;

				sec_val = (sbuf[offset_in_cluster] &
				    (1U << (cluster_idx % 8))) != 0;
				if (bit_val != sec_val)
					stats->diverged_count++;
			} else
				stats->diverged_count++;
		} else if (ctx->num_fats == 2)
			stats->diverged_count++;
	}

	free(cbuf);
	free(sbuf);

	return (0);
}

/*
 * Dump Allocation Bitmap allocation status and contiguous runs (Spec §7.1).
 */
int
util_dump_bitmap(struct faultgen_ctx *ctx, const char *arg)
{
	struct bitmap_info info;
	uint8_t *cbuf;
	uint32_t curr_bitmap_cn, curr_cluster_idx;
	uint32_t end_cn, start_cn;
	uint32_t run_len, run_start;
	uint32_t total_alloc, total_free, total_uncovered;
	int curr_state, error, run_state;
	bool is_single;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (ctx->json) {
		struct bitmap_verify_stats vstats;

		error = bitmap_verify(ctx, &vstats);
		if (error != 0)
			return (error);

		printf("{\n");
		printf("  \"bitmap_summary\": {\n");
		printf("    \"found\": %s,\n",
		    vstats.found ? "true" : "false");
		printf("    \"first_cluster\": %" PRIu32 ",\n",
		    vstats.first_cluster);
		printf("    \"data_length\": %" PRIu64 ",\n",
		    vstats.data_length);
		printf("    \"allocated_clusters\": %" PRIu32 ",\n",
		    vstats.total_alloc);
		printf("    \"free_clusters\": %" PRIu32 ",\n",
		    vstats.total_free);
		printf("    \"uncovered_clusters\": %" PRIu32 ",\n",
		    vstats.uncovered);
		printf("    \"diverged_bits\": %" PRIu32 ",\n",
		    vstats.diverged_count);
		printf("    \"size_errors\": %" PRIu32 "\n",
		    vstats.size_errors);
		printf("  }\n");
		printf("}\n");
		return (0);
	}

	error = bitmap_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	error = parse_cluster_range(arg, ctx->cluster_count, &start_cn,
	    &end_cn, &is_single);
	if (error != 0)
		return (error);

	if (is_single) {
		bool is_set;

		error = bitmap_get_bit(ctx, &info, start_cn, &is_set);
		if (error != 0)
			return (error);

		if (ctx->verbose) {
			uint64_t sector;
			off_t offset;

			sector = exfat_cluster_to_sector(
			    ctx->cluster_heap_offset, ctx->cluster_shift,
			    start_cn);
			offset = (off_t)sector << ctx->sector_shift;
			printf("Cluster %" PRIu32 ": %s (sector %" PRIu64
			    ", offset 0x%" PRIx64 ")\n", start_cn,
			    is_set ? "ALLOCATED" : "FREE", sector,
			    (uint64_t)offset);
		} else {
			printf("Cluster %" PRIu32 ": %s\n", start_cn,
			    is_set ? "ALLOCATED" : "FREE");
		}

		if (ctx->num_fats == 2) {
			struct bitmap_info sec_info;
			bool active_is_sec, sec_val;

			active_is_sec = (exfat_active_fat(ctx) == 1);
			if (bitmap_find_secondary_entry(ctx, !active_is_sec,
			    &sec_info) == 0 &&
			    bitmap_get_bit(ctx, &sec_info, start_cn,
			    &sec_val) == 0)
				printf("  Mirror Bitmap:   %s (%s)\n",
				    sec_val ? "ALLOCATED" : "FREE",
				    (is_set == sec_val) ?
				    "IN SYNC" : "DIVERGED!");
		}
		return (0);
	}

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	curr_bitmap_cn = info.first_cluster;
	error = read_cluster(ctx, curr_bitmap_cn, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}
	curr_cluster_idx = 0;

	if (ctx->verbose) {
		printf("Allocation Bitmap metadata (Spec §7.1):\n");
		printf("  Root dentry:   Cluster %" PRIu32 ", Offset %zu\n",
		    info.dentry_cluster, info.dentry_offset);
		printf("  First cluster: %" PRIu32 "\n", info.first_cluster);
		printf("  Data length:   %" PRIu64 " bytes\n\n",
		    info.data_length);
	}

	printf("Allocation Map (clusters %" PRIu32 " - %" PRIu32 "):\n",
	    start_cn, end_cn);

	total_alloc = 0;
	total_free = 0;
	total_uncovered = 0;
	run_start = start_cn;
	run_len = 0;
	run_state = -1;

	for (uint32_t cn = start_cn; cn <= end_cn; cn++) {
		uint32_t cluster_idx, needed_cluster_idx;
		size_t byte_idx, offset_in_cluster;

		cluster_idx = EXFAT_CNTOI(cn);
		byte_idx = cluster_idx / 8;

		if (byte_idx >= info.data_length) {
			curr_state = 2; /* UNCOVERED */
			total_uncovered++;
		} else {
			needed_cluster_idx = byte_idx / ctx->cluster_size;
			offset_in_cluster = byte_idx % ctx->cluster_size;

			while (curr_cluster_idx < needed_cluster_idx) {
				uint32_t next_cn;

				error = fat_get(ctx, curr_bitmap_cn, &next_cn);
				if (error != 0) {
					free(cbuf);
					return (error);
				}
				if (!exfat_cluster_is_valid(next_cn,
				    ctx->cluster_count)) {
					free(cbuf);
					return (EIO);
				}
				curr_bitmap_cn = next_cn;
				error = read_cluster(ctx, curr_bitmap_cn,
				    cbuf);
				if (error != 0) {
					free(cbuf);
					return (error);
				}
				curr_cluster_idx++;
			}

			if ((cbuf[offset_in_cluster] &
			    (1U << (cluster_idx % 8))) != 0) {
				curr_state = 1; /* ALLOCATED */
				total_alloc++;
			} else {
				curr_state = 0; /* FREE */
				total_free++;
			}
		}

		if (run_state == -1) {
			run_start = cn;
			run_state = curr_state;
			run_len = 1;
		} else if (curr_state == run_state) {
			run_len++;
		} else {
			print_bitmap_run(run_start, run_len, run_state);
			run_start = cn;
			run_state = curr_state;
			run_len = 1;
		}

		if (cn == end_cn)
			break;
	}

	if (run_len > 0)
		print_bitmap_run(run_start, run_len, run_state);

	free(cbuf);

	printf("\nAllocation Summary (Spec §7.1):\n");
	printf("  Inspected range: clusters %" PRIu32 " - %" PRIu32
	    " (%" PRIu32 " clusters)\n", start_cn, end_cn,
	    end_cn - start_cn + 1);
	printf("  Allocated:       %" PRIu32 " clusters (%.2f%%)\n",
	    total_alloc,
	    (double)total_alloc * 100.0 / (end_cn - start_cn + 1));
	printf("  Free:            %" PRIu32 " clusters (%.2f%%)\n",
	    total_free,
	    (double)total_free * 100.0 / (end_cn - start_cn + 1));
	if (total_uncovered > 0)
		printf("  Uncovered:       %" PRIu32 " clusters (%.2f%%)\n",
		    total_uncovered,
		    (double)total_uncovered * 100.0 /
		    (end_cn - start_cn + 1));
	if (ctx->num_fats == 2) {
		struct bitmap_verify_stats vstats;

		if (bitmap_verify(ctx, &vstats) == 0)
			printf("  Mirror Diverged: %" PRIu32 " bit(s)%s\n",
			    vstats.diverged_count,
			    vstats.diverged_count > 0 ? " [DIVERGED]" : "");
	}

	return (0);
}
