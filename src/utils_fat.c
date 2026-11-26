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

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

enum fat_run_type {
	FAT_RUN_NONE = 0,
	FAT_RUN_FREE,
	FAT_RUN_CONTIGUOUS
};

static void	trace_cluster_chain(struct faultgen_ctx *ctx,
		    uint8_t active_fat, uint32_t start_cn);
static int	dump_single_fat_cluster(struct faultgen_ctx *ctx,
		    uint8_t active_fat, uint32_t cn);
static void	flush_fat_run(enum fat_run_type run_type, uint32_t run_start,
		    uint32_t run_len);
static int	dump_fat_range(struct faultgen_ctx *ctx, uint8_t active_fat,
		    uint32_t start_cn, uint32_t end_cn);

/*
 * Trace a cluster chain starting at start_cn with cycle detection (Spec §4.1).
 */
static void
trace_cluster_chain(struct faultgen_ctx *ctx, uint8_t active_fat,
    uint32_t start_cn)
{
	uint32_t count, curr, hare, hare_next, next_cn, tortoise;
	int error;
	bool cycle = false, hare_active = true;

	printf("  Chain trace: %" PRIu32, start_cn);

	curr = start_cn;
	tortoise = start_cn;
	hare = start_cn;
	count = 1;

	for (;;) {
		error = fat_get_entry(ctx, active_fat, curr, &next_cn);
		if (error != 0) {
			printf(" -> [I/O ERROR %d]\n", error);
			return;
		}

		if (EXFAT_FAT_IS_EOF(next_cn)) {
			printf(" -> EOF (%" PRIu32 " %s)\n", count,
			    count == 1 ? "cluster" : "clusters");
			return;
		}

		if (EXFAT_FAT_IS_BAD(next_cn)) {
			printf(" -> 0x%08" PRIX32 " [BAD CLUSTER]\n", next_cn);
			return;
		}

		if (next_cn == EXFAT_FAT_FREE) {
			printf(" -> FREE [UNEXPECTED FREE CLUSTER]\n");
			return;
		}

		if (!exfat_cluster_is_valid(next_cn, ctx->cluster_count)) {
			printf(" -> %" PRIu32 " [OUT OF BOUNDS]\n", next_cn);
			return;
		}

		/* Advance Floyd cycle detector */
		if (hare_active &&
		    fat_get_entry(ctx, active_fat, tortoise, &tortoise) == 0) {
			if (exfat_cluster_is_valid(hare, ctx->cluster_count) &&
			    fat_get_entry(ctx, active_fat, hare,
			    &hare_next) == 0 &&
			    exfat_cluster_is_valid(hare_next,
			    ctx->cluster_count) &&
			    fat_get_entry(ctx, active_fat, hare_next,
			    &hare) == 0 &&
			    exfat_cluster_is_valid(hare, ctx->cluster_count)) {
				if (tortoise == hare)
					cycle = true;
			} else
				hare_active = false;
		}

		count++;
		curr = next_cn;

		if (cycle) {
			printf(" -> %" PRIu32 " [CYCLE DETECTED after %"
			    PRIu32 " clusters]\n", curr, count);
			return;
		}

		if (count <= 10)
			printf(" -> %" PRIu32, curr);
		else if (count == 11)
			printf(" -> ...");

		if (count > ctx->cluster_count) {
			printf(" -> %" PRIu32
			    " [CHAIN EXCEEDS VOLUME CAPACITY]\n", curr);
			return;
		}
	}
}

/*
 * Dump single FAT entry and trace its cluster chain (Spec §4.1).
 */
static int
dump_single_fat_cluster(struct faultgen_ctx *ctx, uint8_t active_fat,
    uint32_t cn)
{
	uint64_t entry_sec;
	off_t entry_off;
	uint32_t entries_per_sec, val;
	int error;

	error = fat_get_entry(ctx, active_fat, cn, &val);
	if (error != 0)
		return (error);

	entries_per_sec = ctx->sector_size / sizeof(uint32_t);
	entry_sec = (uint64_t)ctx->fat_offset +
	    ((uint64_t)active_fat * ctx->fat_length) + (cn / entries_per_sec);
	entry_off = ((off_t)entry_sec << ctx->sector_shift) +
	    (off_t)(cn % entries_per_sec) * sizeof(uint32_t);

	printf("Cluster %" PRIu32 " in FAT %u (Spec §4.1):\n", cn, active_fat);
	printf("  Value:          0x%08" PRIX32, val);
	if (val == EXFAT_FAT_FREE)
		printf(" (FREE)\n");
	else if (EXFAT_FAT_IS_BAD(val))
		printf(" (BAD CLUSTER)\n");
	else if (EXFAT_FAT_IS_EOF(val))
		printf(" (EOF - End of Cluster Chain)\n");
	else if (exfat_cluster_is_valid(val, ctx->cluster_count))
		printf(" (Points to Cluster %" PRIu32 ")\n", val);
	else
		printf(" (OUT OF BOUNDS)\n");

	if (ctx->verbose)
		printf("  On-disk location: Sector %" PRIu64
		    ", Offset 0x%" PRIx64 "\n", entry_sec,
		    (uint64_t)entry_off);

	if (ctx->num_fats == 2) {
		uint8_t inactive_fat;
		uint32_t val2;

		inactive_fat = (active_fat == 0) ? 1 : 0;
		if (fat_get_entry(ctx, inactive_fat, cn, &val2) == 0) {
			if (val == val2)
				printf("  Mirror FAT %u:   0x%08" PRIX32
				    " (IN SYNC)\n", inactive_fat, val2);
			else
				printf("  Mirror FAT %u:   0x%08" PRIX32
				    " (MISMATCH!)\n", inactive_fat, val2);
		}
	}

	if (val != EXFAT_FAT_FREE)
		trace_cluster_chain(ctx, active_fat, cn);

	return (0);
}

/*
 * Flush formatted FAT run.
 */
static void
flush_fat_run(enum fat_run_type run_type, uint32_t run_start, uint32_t run_len)
{
	if (run_len == 0)
		return;

	if (run_type == FAT_RUN_FREE) {
		if (run_len == 1)
			printf("  [%" PRIu32 "]: FREE\n", run_start);
		else
			printf("  [%" PRIu32 " - %" PRIu32 "]: FREE (%" PRIu32
			    " entries)\n", run_start,
			    run_start + run_len - 1, run_len);
	} else if (run_type == FAT_RUN_CONTIGUOUS) {
		if (run_len == 1)
			printf("  [%" PRIu32 "]: %" PRIu32 " (Cluster %" PRIu32
			    ")\n", run_start, run_start + 1, run_start + 1);
		else
			printf("  [%" PRIu32 " - %" PRIu32 "]: Contiguous "
			    "Chain -> %" PRIu32 " .. %" PRIu32 " (%" PRIu32
			    " clusters)\n", run_start,
			    run_start + run_len - 1, run_start + 1,
			    run_start + run_len, run_len);
	}
}

/*
 * Dump cluster entries, runs, and summary across a FAT range (Spec §4.1).
 */
static int
dump_fat_range(struct faultgen_ctx *ctx, uint8_t active_fat, uint32_t start_cn,
    uint32_t end_cn)
{
	uint8_t sec_buf[1U << EXFAT_MAX_SECTOR_SHIFT];
	uint8_t sec_buf1[1U << EXFAT_MAX_SECTOR_SHIFT];
	uint64_t cur_sec, cur_sec1, fat_sec, fat1_sec, total_range_clusters;
	uint32_t diverged_count, entries_per_sec;
	uint32_t run_len, run_start;
	uint32_t total_allocated, total_bad, total_eof, total_free, total_oob;
	int error;
	enum fat_run_type run_type;

	entries_per_sec = ctx->sector_size / sizeof(uint32_t);
	fat_sec = (uint64_t)ctx->fat_offset +
	    ((uint64_t)active_fat * ctx->fat_length);
	fat1_sec = (uint64_t)ctx->fat_offset +
	    ((uint64_t)(1 - active_fat) * ctx->fat_length);

	if (ctx->verbose) {
		printf("File Allocation Table layout (Spec §4.1):\n");
		printf("  Active FAT:     FAT %u\n", active_fat);
		printf("  Number of FATs: %" PRIu8 "\n", ctx->num_fats);
		printf("  FAT offset:     Sector %" PRIu32 " (Offset 0x%"
		    PRIx64 ")\n", ctx->fat_offset,
		    (uint64_t)ctx->fat_offset << ctx->sector_shift);
		printf("  FAT length:     %" PRIu32 " sectors (%" PRIu64
		    " bytes)\n", ctx->fat_length,
		    (uint64_t)ctx->fat_length << ctx->sector_shift);
		printf("  Cluster range:  clusters %" PRIu32 " - %" PRIu32
		    "\n\n", EXFAT_FIRST_CLUSTER,
		    EXFAT_FIRST_CLUSTER + ctx->cluster_count - 1);
	}

	printf("File Allocation Table (FAT %u, entries %" PRIu32 " - %"
	    PRIu32 ", Spec §4.1):\n", active_fat, start_cn, end_cn);

	cur_sec = (uint64_t)-1;
	cur_sec1 = (uint64_t)-1;
	diverged_count = 0;
	total_free = 0;
	total_allocated = 0;
	total_eof = 0;
	total_bad = 0;
	total_oob = 0;

	run_type = FAT_RUN_NONE;
	run_start = start_cn;
	run_len = 0;

	for (uint32_t cn = start_cn; cn <= end_cn; cn++) {
		uint64_t target_sec;
		uint32_t val;
		enum fat_run_type cur_type;

		target_sec = fat_sec + (cn / entries_per_sec);
		if (target_sec != cur_sec) {
			error = read_sector(ctx, target_sec, sec_buf);
			if (error != 0)
				return (error);
			cur_sec = target_sec;
		}
		val = le32dec(sec_buf +
		    (cn % entries_per_sec) * sizeof(uint32_t));

		/* Compare against mirror FAT if dual-FAT volume */
		if (ctx->num_fats == 2) {
			uint64_t target_sec1;
			uint32_t val1;

			target_sec1 = fat1_sec + (cn / entries_per_sec);
			if (target_sec1 != cur_sec1) {
				if (read_sector(ctx, target_sec1,
				    sec_buf1) == 0)
					cur_sec1 = target_sec1;
				else
					cur_sec1 = (uint64_t)-1;
			}
			if (cur_sec1 != (uint64_t)-1) {
				val1 = le32dec(sec_buf1 +
				    (cn % entries_per_sec) * sizeof(uint32_t));
				if (val != val1)
					diverged_count++;
			}
		}

		/* Classify and tally */
		if (val == EXFAT_FAT_FREE) {
			total_free++;
			cur_type = FAT_RUN_FREE;
		} else if (EXFAT_FAT_IS_BAD(val)) {
			total_bad++;
			cur_type = FAT_RUN_NONE;
		} else if (EXFAT_FAT_IS_EOF(val)) {
			total_allocated++;
			total_eof++;
			cur_type = FAT_RUN_NONE;
		} else if (val == cn + 1 &&
		    exfat_cluster_is_valid(val, ctx->cluster_count)) {
			total_allocated++;
			cur_type = FAT_RUN_CONTIGUOUS;
		} else if (exfat_cluster_is_valid(val, ctx->cluster_count)) {
			total_allocated++;
			cur_type = FAT_RUN_NONE;
		} else {
			total_oob++;
			cur_type = FAT_RUN_NONE;
		}

		if (cur_type == run_type && run_type != FAT_RUN_NONE) {
			run_len++;
		} else {
			flush_fat_run(run_type, run_start, run_len);
			if (cur_type == FAT_RUN_NONE) {
				if (EXFAT_FAT_IS_BAD(val))
					printf("  [%" PRIu32 "]: 0x%08" PRIX32
					    " (BAD)\n", cn, val);
				else if (EXFAT_FAT_IS_EOF(val))
					printf("  [%" PRIu32 "]: 0x%08" PRIX32
					    " (EOF)\n", cn, val);
				else if (exfat_cluster_is_valid(val,
				    ctx->cluster_count))
					printf("  [%" PRIu32 "]: %" PRIu32
					    " (Cluster %" PRIu32 ")\n",
					    cn, val, val);
				else
					printf("  [%" PRIu32 "]: 0x%08" PRIX32
					    " (OUT OF BOUNDS)\n", cn, val);
				run_type = FAT_RUN_NONE;
				run_len = 0;
			} else {
				run_type = cur_type;
				run_start = cn;
				run_len = 1;
			}
		}

		if (cn == end_cn)
			break;
	}

	flush_fat_run(run_type, run_start, run_len);

	total_range_clusters = (uint64_t)end_cn - start_cn + 1;
	printf("\nFAT Summary (FAT %u, Spec §4.1):\n", active_fat);
	printf("  Inspected range: clusters %" PRIu32 " - %" PRIu32
	    " (%" PRIu64 " clusters)\n", start_cn, end_cn,
	    total_range_clusters);
	printf("  Allocated:       %" PRIu32 " clusters (%.2f%%)\n",
	    total_allocated,
	    (double)total_allocated * 100.0 / total_range_clusters);
	printf("  Free:            %" PRIu32 " clusters (%.2f%%)\n",
	    total_free,
	    (double)total_free * 100.0 / total_range_clusters);
	printf("  EOF markers:     %" PRIu32 "\n", total_eof);
	printf("  Bad clusters:    %" PRIu32 "\n", total_bad);
	if (total_oob > 0)
		printf("  Out-of-bounds:   %" PRIu32 "\n", total_oob);

	if (ctx->num_fats == 2) {
		if (diverged_count == 0)
			printf("\nDual-FAT Comparison: FAT 0 and FAT 1 are "
			    "identical (IN SYNC)\n");
		else
			printf("\nDual-FAT Comparison: MISMATCH detected! %"
			    PRIu32 " diverged entries in range\n",
			    diverged_count);
	}

	return (0);
}

/*
 * Perform verification of File Allocation Table entries (Spec §4.1).
 */
int
fat_verify(struct faultgen_ctx *ctx, struct fat_verify_stats *stats)
{
	uint8_t *ref_count, *state;
	uint32_t end_cn, max_cn, val0, val1;
	uint8_t active_fat;
	int error;
	bool has_val0, has_val1;

	memset(stats, 0, sizeof(*stats));

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	active_fat = exfat_active_fat(ctx);
	max_cn = EXFAT_FIRST_CLUSTER + ctx->cluster_count - 1;
	end_cn = max_cn;

	has_val0 = (fat_get_entry(ctx, active_fat, 0, &val0) == 0);
	if (has_val0 && val0 != 0xFFFFFFF8U)
		stats->total_oob++;
	has_val1 = (fat_get_entry(ctx, active_fat, 1, &val1) == 0);
	if (has_val1 && val1 != EXFAT_FAT_EOF)
		stats->total_oob++;
	if (ctx->num_fats == 2) {
		uint32_t sec0, sec1;

		if (has_val0 &&
		    fat_get_entry(ctx, 1 - active_fat, 0, &sec0) == 0 &&
		    sec0 != val0)
			stats->diverged_count++;
		if (has_val1 &&
		    fat_get_entry(ctx, 1 - active_fat, 1, &sec1) == 0 &&
		    sec1 != val1)
			stats->diverged_count++;
	}

	state = calloc(ctx->cluster_count, 1);
	ref_count = calloc(ctx->cluster_count, 1);
	if (ref_count != NULL) {
		struct bitmap_info bminfo, sec_bminfo;
		struct upcase_info ucinfo;
		uint32_t sys_cns[4];
		size_t nsys = 0;

		if (exfat_cluster_is_valid(ctx->root_dir_cluster,
		    ctx->cluster_count))
			sys_cns[nsys++] = ctx->root_dir_cluster;
		if (bitmap_find_entry(ctx, &bminfo) == 0 &&
		    exfat_cluster_is_valid(bminfo.first_cluster,
		    ctx->cluster_count))
			sys_cns[nsys++] = bminfo.first_cluster;
		if (ctx->num_fats == 2 &&
		    bitmap_find_secondary_entry(ctx, active_fat == 0,
		    &sec_bminfo) == 0 &&
		    exfat_cluster_is_valid(sec_bminfo.first_cluster,
		    ctx->cluster_count))
			sys_cns[nsys++] = sec_bminfo.first_cluster;
		if (upcase_find_entry(ctx, &ucinfo) == 0 &&
		    exfat_cluster_is_valid(ucinfo.first_cluster,
		    ctx->cluster_count))
			sys_cns[nsys++] = ucinfo.first_cluster;

		for (size_t i = 0; i < nsys; i++) {
			uint32_t idx = EXFAT_CNTOI(sys_cns[i]);

			if (ref_count[idx] > 0)
				stats->crosslink_count++;
			else
				ref_count[idx] = 1;
		}
	}

	for (uint32_t cn = EXFAT_FIRST_CLUSTER; cn <= end_cn; cn++) {
		uint32_t val;

		error = fat_get_entry(ctx, active_fat, cn, &val);
		if (error != 0) {
			free(ref_count);
			free(state);
			return (error);
		}

		if (val == EXFAT_FAT_FREE) {
			stats->total_free++;
		} else if (EXFAT_FAT_IS_BAD(val)) {
			stats->total_bad++;
		} else if (EXFAT_FAT_IS_EOF(val)) {
			stats->total_eof++;
			stats->total_allocated++;
		} else if (exfat_cluster_is_valid(val, ctx->cluster_count)) {
			stats->total_allocated++;
			if (ref_count != NULL && val != cn) {
				uint32_t tidx = EXFAT_CNTOI(val);

				if (ref_count[tidx] > 0)
					stats->crosslink_count++;
				else
					ref_count[tidx] = 1;
			}
			if (state == NULL) {
				if (val == cn)
					stats->cycle_count++;
			} else if (state[EXFAT_CNTOI(cn)] == 0) {
				uint32_t curr;

				curr = cn;
				while (exfat_cluster_is_valid(curr,
				    ctx->cluster_count)) {
					uint32_t idx, next_val;

					idx = EXFAT_CNTOI(curr);
					if (state[idx] == 1) {
						stats->cycle_count++;
						break;
					}
					if (state[idx] == 2)
						break;
					state[idx] = 1;
					if (fat_get_entry(ctx, active_fat,
					    curr, &next_val) != 0)
						break;
					curr = next_val;
				}
				curr = cn;
				while (exfat_cluster_is_valid(curr,
				    ctx->cluster_count)) {
					uint32_t idx, next_val;

					idx = EXFAT_CNTOI(curr);
					if (state[idx] != 1)
						break;
					state[idx] = 2;
					if (fat_get_entry(ctx, active_fat,
					    curr, &next_val) != 0)
						break;
					curr = next_val;
				}
			}
		} else
			stats->total_oob++;

		if (ctx->num_fats == 2) {
			uint32_t val_sec;

			error = fat_get_entry(ctx, 1 - active_fat, cn,
			    &val_sec);
			if (error == 0 && val != val_sec)
				stats->diverged_count++;
		}

		if (cn == end_cn)
			break;
	}

	free(ref_count);
	free(state);
	return (0);
}

/*
 * Dump File Allocation Table entries, chains, and summary (Spec §4.1).
 */
int
util_dump_fat(struct faultgen_ctx *ctx, const char *arg)
{
	uint32_t end_cn, start_cn;
	uint8_t active_fat;
	int error;
	bool is_single;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	active_fat = exfat_active_fat(ctx);

	if (ctx->json) {
		struct fat_verify_stats vstats;

		error = fat_verify(ctx, &vstats);
		if (error != 0)
			return (error);

		printf("{\n");
		printf("  \"fat_summary\": {\n");
		printf("    \"active_fat\": %u,\n", active_fat);
		printf("    \"cluster_count\": %" PRIu32 ",\n",
		    ctx->cluster_count);
		printf("    \"allocated_clusters\": %" PRIu32 ",\n",
		    vstats.total_allocated);
		printf("    \"free_clusters\": %" PRIu32 ",\n",
		    vstats.total_free);
		printf("    \"eof_markers\": %" PRIu32 ",\n",
		    vstats.total_eof);
		printf("    \"bad_clusters\": %" PRIu32 ",\n",
		    vstats.total_bad);
		printf("    \"out_of_bounds\": %" PRIu32 ",\n",
		    vstats.total_oob);
		printf("    \"cycles\": %" PRIu32 ",\n",
		    vstats.cycle_count);
		printf("    \"mirror_diverged\": %" PRIu32 "\n",
		    vstats.diverged_count);
		printf("  }\n");
		printf("}\n");
		return (0);
	}

	error = parse_cluster_range(arg, ctx->cluster_count, &start_cn, &end_cn,
	    &is_single);
	if (error != 0)
		return (error);

	if (is_single)
		return (dump_single_fat_cluster(ctx, active_fat, start_cn));

	return (dump_fat_range(ctx, active_fat, start_cn, end_cn));
}
