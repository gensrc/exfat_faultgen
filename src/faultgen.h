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

#ifndef _FAULTGEN_H_
#define _FAULTGEN_H_

#include <stdbool.h>
#include <stdint.h>

#include "exfat_ondisk.h"
#include "io.h"
#include "subr.h"

#ifndef nitems
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#endif

struct faultgen_ctx {
	const char			*image_path;
	int				 fd;
	bool				 dry_run;
	bool				 verbose;
	bool				 json;
	struct exfat_boot_sector	 bs;
	uint32_t			 sector_size;
	uint32_t			 cluster_size;
	uint8_t				 sector_shift;
	uint8_t				 cluster_shift;
	uint32_t			 fat_offset;
	uint32_t			 fat_length;
	uint32_t			 cluster_heap_offset;
	uint32_t			 cluster_count;
	uint32_t			 root_dir_cluster;
	uint16_t			 volume_flags;
	uint8_t				 num_fats;
};

/*
 * Return active FAT index (0 for First FAT, 1 for Second FAT) per
 * Spec §3.1.13.1.  ActiveFat is valid only when NumberOfFats is 2.
 */
static inline uint8_t
exfat_active_fat(const struct faultgen_ctx *ctx)
{
	if (ctx != NULL && ctx->num_fats > 1 &&
	    (ctx->volume_flags & EXFAT_VOL_ACTIVE_FAT) != 0)
		return (1);
	return (0);
}

struct fault_handler {
	const char	*opt_name;
	int		 val;
	int		 has_arg;
	const char	*arg_desc;
	const char	*desc;
	bool		 is_utility;
	int		(*apply)(struct faultgen_ctx *ctx, const char *arg);
};

/*
 * Fault handler prototypes.
 * Each handler returns 0 on success, or a positive errno value on failure.
 */
int	fault_boot_checksum_mismatch(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_boot_backup_mismatch(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_boot_flags_reserved(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_boot_percent_in_use(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_boot_drive_select(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_boot_zero_fields(struct faultgen_ctx *ctx,
	    const char *arg);

int	fault_fat_cycle(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_fat_bad_cluster(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_fat_crosslink(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_fat_out_of_bounds(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_fat_mirror_diverge(struct faultgen_ctx *ctx,
	    const char *arg);

int	fault_bitmap_orphan(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_bitmap_false_free(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_bitmap_truncate(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_bitmap_mirror_diverge(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_bitmap_flags_reserved(struct faultgen_ctx *ctx,
	    const char *arg);

int	fault_dentry_checksum(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_stream_vdl_exceeds_dl(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_stream_nofatchain_fragment(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_orphaned_secondary(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_root_in_subdir(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_secondary_count(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_name_hash(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_invalid_name_chars(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_dentry_size_mismatch(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_upcase_checksum_mismatch(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_upcase_truncate(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_label_duplicate(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_label_invalid_chars(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_label_length(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_guid_duplicate(struct faultgen_ctx *ctx,
	    const char *arg);
int	fault_guid_invalid(struct faultgen_ctx *ctx,
	    const char *arg);

/*
 * Utility handler prototypes (utils_xxx.c).
 */
int	util_dump_all(struct faultgen_ctx *ctx,
	    const char *arg);
int	util_dump_boot(struct faultgen_ctx *ctx,
	    const char *arg);
int	util_dump_fat(struct faultgen_ctx *ctx,
	    const char *arg);
int	util_dump_bitmap(struct faultgen_ctx *ctx,
	    const char *arg);
int	util_dump_dentries(struct faultgen_ctx *ctx,
	    const char *arg);
int	util_verify(struct faultgen_ctx *ctx,
	    const char *arg);

/*
 * Boot Region verification helpers (utils_boot.c).
 */
struct boot_verify_stats {
	bool		main_valid;
	bool		backup_valid;
	bool		backup_matches_main;
	uint32_t	param_errors;
};

int	boot_verify(struct faultgen_ctx *ctx,
	    struct boot_verify_stats *stats);
int	calc_boot_region_checksum(struct faultgen_ctx *ctx, uint64_t start_sec,
	    uint32_t *csum_out);
int	read_boot_sector(struct faultgen_ctx *ctx, uint64_t sector,
	    uint8_t **buf_out);

/*
 * File Allocation Table verification helpers (utils_fat.c).
 */
struct fat_verify_stats {
	uint32_t	total_allocated;
	uint32_t	total_free;
	uint32_t	total_eof;
	uint32_t	total_bad;
	uint32_t	total_oob;
	uint32_t	cycle_count;
	uint32_t	crosslink_count;
	uint32_t	diverged_count;
};

int	fat_verify(struct faultgen_ctx *ctx,
	    struct fat_verify_stats *stats);

/*
 * Allocation Bitmap inspection & verification helpers (utils_bitmap.c).
 */
struct bitmap_info {
	uint32_t	first_cluster;
	uint64_t	data_length;
	uint32_t	dentry_cluster;
	size_t		dentry_offset;
	uint8_t		fat_idx;
};

struct bitmap_verify_stats {
	bool		found;
	uint32_t	first_cluster;
	uint64_t	data_length;
	uint32_t	total_alloc;
	uint32_t	total_free;
	uint32_t	uncovered;
	uint32_t	size_errors;
	uint32_t	diverged_count;
	uint32_t	sync_errors;
};

int	bitmap_find_entry(struct faultgen_ctx *ctx,
	    struct bitmap_info *info);
int	bitmap_find_secondary_entry(struct faultgen_ctx *ctx,
	    bool target_second, struct bitmap_info *info);
int	bitmap_get_bit(struct faultgen_ctx *ctx,
	    const struct bitmap_info *info, uint32_t cn, bool *val);
int	bitmap_set_bit(struct faultgen_ctx *ctx,
	    const struct bitmap_info *info, uint32_t cn, bool val);
int	bitmap_verify(struct faultgen_ctx *ctx,
	    struct bitmap_verify_stats *stats);

/*
 * Directory Entry traversal and verification helpers (utils_dentry.c).
 */
struct upcase_info {
	uint32_t	first_cluster;
	uint64_t	data_length;
	uint32_t	table_checksum;
	uint32_t	dentry_cluster;
	size_t		dentry_offset;
};

int	upcase_find_entry(struct faultgen_ctx *ctx,
	    struct upcase_info *info);

struct dentry_stats {
	size_t		dir_count;
	size_t		entry_set_count;
	size_t		file_count;
	size_t		subdir_count;
	size_t		bitmap_count;
	size_t		upcase_count;
	size_t		label_count;
	size_t		guid_count;
	size_t		deleted_count;
	size_t		csum_mismatch_count;
	size_t		hash_mismatch_count;
	size_t		orphaned_secondary_count;
	size_t		anomalies_count;
};

uint16_t	calc_utf16_name_hash(const uint16_t *name, size_t nchars,
		    const uint16_t *upcase_table);
int	dentry_scan_tree(struct faultgen_ctx *ctx, const char *target,
	    struct dentry_stats *stats, bool verbose);
void	extract_dentry_name(const union exfat_dentry *dent_set,
	    uint8_t sec_count, char *name_buf, size_t buf_size);
size_t	extract_dentry_utf16(const union exfat_dentry *dent_set,
	    uint8_t sec_count, uint16_t *utf16_buf, size_t max_chars);
bool	is_valid_volume_label(const uint16_t *label, size_t nchars);
int	load_upcase_table(struct faultgen_ctx *ctx, uint16_t **table_out);

#endif /* _FAULTGEN_H_ */
