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
#include "subr.h"

static void	scan_dir_nofatchain_streams(struct faultgen_ctx *ctx,
		    uint32_t first_cn, bool no_fat_chain, uint64_t data_len,
		    uint8_t *ref_bm, uint8_t *visited_dirs);
static uint32_t	count_orphan_bitmap_clusters(struct faultgen_ctx *ctx);
static void	print_json_report(struct faultgen_ctx *ctx,
		    const struct boot_verify_stats *bs,
		    const struct fat_verify_stats *fs,
		    const struct bitmap_verify_stats *bms,
		    const struct dentry_stats *ds,
		    uint32_t boot_err, uint32_t fat_err,
		    uint32_t bm_err, uint32_t dentry_err,
		    uint32_t total_err);

/*
 * Recursively scan a directory and its subdirectories to mark all clusters
 * referenced by streams (including NoFatChain streams) in ref_bm.
 */
static void
scan_dir_nofatchain_streams(struct faultgen_ctx *ctx, uint32_t first_cn,
    bool no_fat_chain, uint64_t data_len, uint8_t *ref_bm,
    uint8_t *visited_dirs)
{
	uint8_t *cbuf;
	uint64_t max_dir_clusters;
	uint32_t cur_cn, dir_idx;
	bool is_dir_entry;

	if (!exfat_cluster_is_valid(first_cn, ctx->cluster_count))
		return;

	dir_idx = EXFAT_CNTOI(first_cn);
	if ((visited_dirs[dir_idx / 8] & (1U << (dir_idx % 8))) != 0)
		return;
	visited_dirs[dir_idx / 8] |= (uint8_t)(1U << (dir_idx % 8));

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return;

	if (no_fat_chain && data_len > 0) {
		if (data_len > EXFAT_MAX_DIR_SIZE)
			data_len = EXFAT_MAX_DIR_SIZE;
		max_dir_clusters = howmany(data_len, ctx->cluster_size);
	} else
		max_dir_clusters = EXFAT_MAX_DIR_SIZE / ctx->cluster_size;
	if (max_dir_clusters > ctx->cluster_count)
		max_dir_clusters = ctx->cluster_count;

	cur_cn = first_cn;
	is_dir_entry = false;
	for (uint64_t step = 0; step < max_dir_clusters &&
	    exfat_cluster_is_valid(cur_cn, ctx->cluster_count); step++) {
		union exfat_dentry *dentries;
		size_t nslots;
		uint32_t cidx, next_cn;

		cidx = EXFAT_CNTOI(cur_cn);
		ref_bm[cidx / 8] |= (uint8_t)(1U << (cidx % 8));
		if (step > 0) {
			if ((visited_dirs[cidx / 8] &
			    (1U << (cidx % 8))) != 0)
				break;
			visited_dirs[cidx / 8] |=
			    (uint8_t)(1U << (cidx % 8));
		}

		if (read_cluster(ctx, cur_cn, cbuf) != 0)
			break;
		nslots = ctx->cluster_size / sizeof(union exfat_dentry);
		dentries = (union exfat_dentry *)cbuf;
		for (size_t s = 0; s < nslots; s++) {
			uint64_t dl, ncl;
			uint32_t scn;
			uint8_t type;
			bool sub_nfc;

			type = dentries[s].type;
			if (type == EXFAT_ENTRY_EOD)
				goto done_dir;
			if (type == EXFAT_ENTRY_FILE) {
				uint16_t attr;

				attr = le16toh(
				    dentries[s].file.fe_file_attributes);
				is_dir_entry =
				    ((attr & EXFAT_ATTR_DIRECTORY) != 0);
				continue;
			}
			if (type != EXFAT_ENTRY_STREAM &&
			    type != EXFAT_ENTRY_VENDOR_ALLOC) {
				if ((type & EXFAT_ENTRY_TYPE_SECONDARY) == 0)
					is_dir_entry = false;
				continue;
			}
			scn = le32toh(dentries[s].stream.se_first_cluster);
			dl = le64toh(dentries[s].stream.se_data_length);
			sub_nfc = (dentries[s].stream.se_general_flags &
			    EXFAT_FLAG_NO_FAT_CHAIN) != 0;
			if (dl > 0 &&
			    exfat_cluster_is_valid(scn, ctx->cluster_count)) {
				ncl = (dl / ctx->cluster_size) +
				    ((dl % ctx->cluster_size) != 0);
				if (ncl > ctx->cluster_count)
					ncl = ctx->cluster_count;
				for (uint64_t k = 0; k < ncl; k++) {
					uint64_t c64 = (uint64_t)scn + k;
					uint32_t c, idx;

					if (c64 > UINT32_MAX ||
					    !exfat_cluster_is_valid(
					    (uint32_t)c64, ctx->cluster_count))
						break;
					c = (uint32_t)c64;
					idx = EXFAT_CNTOI(c);
					ref_bm[idx / 8] |=
					    (uint8_t)(1U << (idx % 8));
					if (!sub_nfc)
						break;
				}
			}
			if (type == EXFAT_ENTRY_STREAM && is_dir_entry &&
			    exfat_cluster_is_valid(scn, ctx->cluster_count)) {
				is_dir_entry = false;
				scan_dir_nofatchain_streams(ctx, scn, sub_nfc,
				    dl, ref_bm, visited_dirs);
			}
		}

		if (no_fat_chain && data_len > 0)
			next_cn = cur_cn + 1;
		else if (fat_get(ctx, cur_cn, &next_cn) != 0 ||
		    !exfat_cluster_is_valid(next_cn, ctx->cluster_count))
			break;
		cur_cn = next_cn;
	}
done_dir:
	free(cbuf);
}

/*
 * Mark a valid cluster number as referenced in ref_bm.
 */
static inline void
mark_valid_cluster(const struct faultgen_ctx *ctx, uint8_t *ref_bm,
    uint32_t cn)
{
	if (exfat_cluster_is_valid(cn, ctx->cluster_count)) {
		uint32_t idx = EXFAT_CNTOI(cn);

		ref_bm[idx / 8] |= (uint8_t)(1U << (idx % 8));
	}
}

/*
 * Check whether any allocated cluster in the bitmap is unreferenced by the
 * active FAT, system streams, or NoFatChain streams (Spec §7.1).
 */
static uint32_t
count_orphan_bitmap_clusters(struct faultgen_ctx *ctx)
{
	struct bitmap_info bminfo, sec_bminfo;
	struct upcase_info ucinfo;
	uint8_t *ref_bm, *visited_dirs;
	uint32_t max_cn, orphans;
	bool has_bm, has_sec_bm, has_uc;

	orphans = 0;
	has_bm = (bitmap_find_entry(ctx, &bminfo) == 0);
	has_sec_bm = false;
	if (ctx->num_fats == 2) {
		bool active_is_sec;

		active_is_sec = (exfat_active_fat(ctx) == 1);
		has_sec_bm = (bitmap_find_secondary_entry(ctx, !active_is_sec,
		    &sec_bminfo) == 0);
	}
	has_uc = (upcase_find_entry(ctx, &ucinfo) == 0);
	if (!has_bm)
		return (0);

	ref_bm = calloc(howmany(ctx->cluster_count, 8), 1);
	if (ref_bm == NULL)
		return (0);
	visited_dirs = calloc(howmany(ctx->cluster_count, 8), 1);
	if (visited_dirs == NULL) {
		free(ref_bm);
		return (0);
	}

	/* Mark any cluster with a non-free FAT entry or pointed to by FAT */
	max_cn = EXFAT_FIRST_CLUSTER + ctx->cluster_count - 1;
	for (uint32_t cn = EXFAT_FIRST_CLUSTER; cn <= max_cn; cn++) {
		uint32_t fat_val, idx;

		if (fat_get(ctx, cn, &fat_val) == 0 &&
		    fat_val != EXFAT_FAT_FREE) {
			idx = EXFAT_CNTOI(cn);
			ref_bm[idx / 8] |= (uint8_t)(1U << (idx % 8));
			if (exfat_cluster_is_valid(fat_val,
			    ctx->cluster_count)) {
				uint32_t tidx = EXFAT_CNTOI(fat_val);

				ref_bm[tidx / 8] |=
				    (uint8_t)(1U << (tidx % 8));
			}
		}
		if (cn == max_cn)
			break;
	}

	/* Mark system starting clusters */
	mark_valid_cluster(ctx, ref_bm, ctx->root_dir_cluster);
	mark_valid_cluster(ctx, ref_bm, bminfo.first_cluster);
	if (has_sec_bm)
		mark_valid_cluster(ctx, ref_bm, sec_bminfo.first_cluster);
	if (has_uc)
		mark_valid_cluster(ctx, ref_bm, ucinfo.first_cluster);

	/* Recursively scan directory tree for NoFatChain stream allocations */
	scan_dir_nofatchain_streams(ctx, ctx->root_dir_cluster, false, 0,
	    ref_bm, visited_dirs);
	free(visited_dirs);

	for (uint32_t cn = EXFAT_FIRST_CLUSTER; cn <= max_cn; cn++) {
		uint32_t idx;
		bool is_ref, is_set;

		idx = EXFAT_CNTOI(cn);
		if (bitmap_get_bit(ctx, &bminfo, cn, &is_set) == 0) {
			is_ref = (ref_bm[idx / 8] & (1U << (idx % 8))) != 0;
			if (is_set && !is_ref)
				orphans++;
			else if (!is_set && is_ref) {
				uint32_t fat_val;

				/*
				 * Count false-free NoFatChain clusters not
				 * already flagged by bitmap_verify().
				 */
				if (cn != ctx->root_dir_cluster &&
				    cn != bminfo.first_cluster &&
				    (!has_sec_bm ||
				    cn != sec_bminfo.first_cluster) &&
				    (!has_uc ||
				    cn != ucinfo.first_cluster) &&
				    (fat_get(ctx, cn, &fat_val) != 0 ||
				    fat_val == EXFAT_FAT_FREE))
					orphans++;
			}
		}
		if (cn == max_cn)
			break;
	}
	free(ref_bm);
	return (orphans);
}

/*
 * Output verification results in machine-readable JSON format.
 */
static void
print_json_report(struct faultgen_ctx *ctx,
    const struct boot_verify_stats *bs,
    const struct fat_verify_stats *fs,
    const struct bitmap_verify_stats *bms,
    const struct dentry_stats *ds,
    uint32_t boot_err, uint32_t fat_err,
    uint32_t bm_err, uint32_t dentry_err,
    uint32_t total_err)
{
	printf("{\n");
	printf("  \"target\": ");
	print_json_string(ctx->image_path, strlen(ctx->image_path));
	printf(",\n");
	printf("  \"status\": \"%s\",\n", total_err == 0 ? "clean" : "corrupt");
	printf("  \"total_defects\": %" PRIu32 ",\n", total_err);
	printf("  \"volume_info\": {\n");
	printf("    \"fs_name\": ");
	print_json_string((const char *)ctx->bs.bs_fs_name,
	    sizeof(ctx->bs.bs_fs_name));
	printf(",\n");
	printf("    \"volume_serial\": \"0x%08" PRIX32 "\",\n",
	    le32toh(ctx->bs.bs_volume_serial));
	printf("    \"sector_size\": %u,\n", ctx->sector_size);
	printf("    \"cluster_size\": %u,\n", ctx->cluster_size);
	printf("    \"cluster_count\": %" PRIu32 ",\n", ctx->cluster_count);
	printf("    \"number_of_fats\": %u\n", ctx->num_fats);
	printf("  },\n");
	printf("  \"components\": {\n");
	printf("    \"boot\": {\n");
	printf("      \"status\": \"%s\",\n",
	    boot_err == 0 ? "pass" : "fail");
	printf("      \"main_checksum_valid\": %s,\n",
	    bs->main_valid ? "true" : "false");
	printf("      \"backup_matches_main\": %s,\n",
	    bs->backup_matches_main ? "true" : "false");
	printf("      \"backup_checksum_valid\": %s,\n",
	    bs->backup_valid ? "true" : "false");
	printf("      \"parameter_errors\": %" PRIu32 ",\n",
	    bs->param_errors);
	printf("      \"defects\": %" PRIu32 "\n", boot_err);
	printf("    },\n");
	printf("    \"fat\": {\n");
	printf("      \"status\": \"%s\",\n",
	    fat_err == 0 ? "pass" : "fail");
	printf("      \"allocated_clusters\": %" PRIu32 ",\n",
	    fs->total_allocated);
	printf("      \"free_clusters\": %" PRIu32 ",\n",
	    fs->total_free);
	printf("      \"bad_clusters\": %" PRIu32 ",\n",
	    fs->total_bad);
	printf("      \"out_of_bounds\": %" PRIu32 ",\n",
	    fs->total_oob);
	printf("      \"cycles\": %" PRIu32 ",\n",
	    fs->cycle_count);
	printf("      \"crosslinks\": %" PRIu32 ",\n",
	    fs->crosslink_count);
	printf("      \"mirror_diverged\": %" PRIu32 ",\n",
	    fs->diverged_count);
	printf("      \"defects\": %" PRIu32 "\n", fat_err);
	printf("    },\n");
	printf("    \"bitmap\": {\n");
	printf("      \"status\": \"%s\",\n",
	    bm_err == 0 ? "pass" : "fail");
	printf("      \"found\": %s,\n",
	    bms->found ? "true" : "false");
	printf("      \"allocated_clusters\": %" PRIu32 ",\n",
	    bms->total_alloc);
	printf("      \"free_clusters\": %" PRIu32 ",\n",
	    bms->total_free);
	printf("      \"uncovered_clusters\": %" PRIu32 ",\n",
	    bms->uncovered);
	printf("      \"diverged_bits\": %" PRIu32 ",\n",
	    bms->diverged_count);
	printf("      \"size_errors\": %" PRIu32 ",\n",
	    bms->size_errors);
	printf("      \"sync_errors\": %" PRIu32 ",\n",
	    bms->sync_errors);
	printf("      \"defects\": %" PRIu32 "\n", bm_err);
	printf("    },\n");
	printf("    \"dentries\": {\n");
	printf("      \"status\": \"%s\",\n",
	    dentry_err == 0 ? "pass" : "fail");
	printf("      \"directories\": %zu,\n", ds->dir_count);
	printf("      \"files\": %zu,\n", ds->file_count);
	printf("      \"checksum_mismatches\": %zu,\n",
	    ds->csum_mismatch_count);
	printf("      \"hash_mismatches\": %zu,\n",
	    ds->hash_mismatch_count);
	printf("      \"orphaned_secondaries\": %zu,\n",
	    ds->orphaned_secondary_count);
	printf("      \"anomalies\": %zu,\n", ds->anomalies_count);
	printf("      \"defects\": %" PRIu32 "\n", dentry_err);
	printf("    }\n");
	printf("  }\n");
	printf("}\n");
}

/*
 * Perform comprehensive volume verification across all on-disk structures.
 */
int
util_verify(struct faultgen_ctx *ctx, const char *arg)
{
	struct boot_verify_stats bstats;
	struct fat_verify_stats fstats;
	struct bitmap_verify_stats bmstats;
	struct dentry_stats dstats;
	uint32_t bm_defects, boot_defects, dentry_defects, fat_defects;
	uint32_t total_defects;
	int error;

	(void)arg;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = boot_verify(ctx, &bstats);
	if (error != 0)
		return (error);

	error = fat_verify(ctx, &fstats);
	if (error != 0)
		return (error);

	error = bitmap_verify(ctx, &bmstats);
	if (error != 0)
		return (error);

	error = dentry_scan_tree(ctx, NULL, &dstats, false);
	if (error != 0)
		return (error);

	boot_defects = (!bstats.main_valid ? 1 : 0) +
	    (!bstats.backup_valid ? 1 : 0) +
	    (!bstats.backup_matches_main ? 1 : 0) +
	    bstats.param_errors;

	fat_defects = fstats.total_oob + fstats.cycle_count +
	    fstats.crosslink_count + fstats.diverged_count + fstats.total_bad;

	bmstats.sync_errors += count_orphan_bitmap_clusters(ctx);

	bm_defects = (!bmstats.found ? 1 : 0) + bmstats.size_errors +
	    bmstats.uncovered + bmstats.diverged_count + bmstats.sync_errors;

	dentry_defects = (uint32_t)dstats.csum_mismatch_count +
	    (uint32_t)dstats.anomalies_count;

	total_defects = boot_defects + fat_defects + bm_defects +
	    dentry_defects;

	if (ctx->json) {
		print_json_report(ctx, &bstats, &fstats, &bmstats, &dstats,
		    boot_defects, fat_defects, bm_defects, dentry_defects,
		    total_defects);
		if (total_defects > 0)
			return (EBADMSG);
		return (0);
	}

	print_divider('=');
	printf("                     exFAT Volume Verification Report\n");
	print_divider('=');
	printf("Target Image:  %s\n", ctx->image_path);
	printf("File System:   %.8s\n", ctx->bs.bs_fs_name);
	printf("Volume Serial: %04" PRIX32 "-%04" PRIX32 " (0x%08" PRIX32 ")\n",
	    le32toh(ctx->bs.bs_volume_serial) >> 16,
	    le32toh(ctx->bs.bs_volume_serial) & 0xFFFF,
	    le32toh(ctx->bs.bs_volume_serial));
	printf("Geometry:      %" PRIu32 " clusters (%" PRIu32 " B/cluster), %u"
	    " FAT(s)\n", ctx->cluster_count, ctx->cluster_size, ctx->num_fats);
	printf("\nComponent Verification:\n");

	if (boot_defects == 0) {
		printf("  [PASS] Boot Region (Spec §3):\n");
		printf("         Parameters, Backup VBR, and Checksums "
		    "verified\n");
	} else {
		printf("  [FAIL] Boot Region (Spec §3):\n");
		printf("         %" PRIu32 " defect(s) detected\n",
		    boot_defects);
	}

	if (fat_defects == 0) {
		printf("  [PASS] File Allocation Table (Spec §4):\n");
		printf("         %" PRIu32 " allocated, %" PRIu32 " free, "
		    "no cycles or out-of-bounds\n",
		    fstats.total_allocated, fstats.total_free);
	} else {
		printf("  [FAIL] File Allocation Table (Spec §4):\n");
		printf("         %" PRIu32 " defect(s) detected\n",
		    fat_defects);
	}

	if (bm_defects == 0) {
		printf("  [PASS] Allocation Bitmap (Spec §7.1):\n");
		printf("         Bitmap valid, %" PRIu32 " clusters allocated, "
		    "%" PRIu32 " free\n", bmstats.total_alloc,
		    bmstats.total_free);
	} else {
		printf("  [FAIL] Allocation Bitmap (Spec §7.1):\n");
		printf("         %" PRIu32 " defect(s) detected\n", bm_defects);
	}

	if (dentry_defects == 0) {
		printf("  [PASS] Directory Hierarchy (Spec §6, §7):\n");
		printf("         %zu directories, %zu files, all SetChecksums "
		    "valid\n", dstats.dir_count, dstats.file_count);
	} else {
		printf("  [FAIL] Directory Hierarchy (Spec §6, §7):\n");
		printf("         %" PRIu32 " defect(s) detected (%zu checksum "
		    "mismatches, %zu anomalies)\n", dentry_defects,
		    dstats.csum_mismatch_count, dstats.anomalies_count);
	}

	printf("\n");
	print_divider('-');
	if (total_defects == 0)
		printf("Verification Result: VOLUME CLEAN (0 defects "
		    "detected)\n");
	else
		printf("Verification Result: VOLUME CORRUPT (%" PRIu32
		    " defect(s) detected)\n", total_defects);
	print_divider('-');

	if (total_defects > 0)
		return (EBADMSG);

	return (0);
}
