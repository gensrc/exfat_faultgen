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
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

struct dentry_loc {
	uint32_t	cluster;
	size_t		slot_idx;
	uint8_t		*cbuf;
};

static bool	dentry_matches_target(const union exfat_dentry *dent_set,
		    uint8_t sec_count, size_t file_index, const char *target);
static int	create_sample_entry(struct faultgen_ctx *ctx,
		    union exfat_dentry *dent, size_t slot_idx,
		    size_t entries_per_cluster, const char *name, bool is_dir,
		    uint32_t first_cn);
static int	find_or_create_dentry(struct faultgen_ctx *ctx,
		    const char *target, bool is_dir, uint32_t default_first_cn,
		    struct dentry_loc *loc);
static int	find_root_entry_by_type(struct faultgen_ctx *ctx,
		    uint8_t target_type, struct dentry_loc *loc);
static int	find_root_available_slot(struct faultgen_ctx *ctx,
		    uint32_t skip_cluster, size_t skip_slot,
		    struct dentry_loc *loc);
static int	find_or_alloc_root_entry(struct faultgen_ctx *ctx,
		    uint8_t target_type, struct dentry_loc *loc,
		    bool *created_out);
static void	write_single_root_dentry(union exfat_dentry *dentries,
		    size_t slot_idx, size_t entries_per_cluster,
		    const union exfat_dentry *new_dent);

/*
 * Check whether a directory entry set matches the user target (name or index).
 */
static bool
dentry_matches_target(const union exfat_dentry *dent_set, uint8_t sec_count,
    size_t file_index, const char *target)
{
	char name_buf[EXFAT_MAX_NAME_CHARS * 3 + 1];
	uint32_t idx;

	if (target == NULL || *target == '\0')
		return (true);

	extract_dentry_name(dent_set, sec_count, name_buf, sizeof(name_buf));
	if (strcasecmp(name_buf, target) == 0)
		return (true);

	if (parse_u32_str(target, NULL, &idx) == 0) {
		if (idx == file_index)
			return (true);
		if (sec_count >= 1 &&
		    dent_set[1].type == EXFAT_ENTRY_STREAM &&
		    le32toh(dent_set[1].stream.se_first_cluster) == idx)
			return (true);
	}

	return (false);
}

/*
 * Create a sample file or directory entry set in the directory cluster.
 */
static int
create_sample_entry(struct faultgen_ctx *ctx, union exfat_dentry *dent,
    size_t slot_idx, size_t entries_per_cluster, const char *name,
    bool is_dir, uint32_t first_cn)
{
	const char *sample_name;
	size_t name_len;
	uint16_t utf16_name[EXFAT_CHARS_PER_NAME_ENTRY];
	uint16_t *upcase_table;
	uint16_t hash;
	bool was_eod;

	sample_name = (name != NULL && *name != '\0') ?
	    name : (is_dir ? "subdir" : "sample.txt");
	name_len = strlen(sample_name);
	if (name_len > EXFAT_CHARS_PER_NAME_ENTRY)
		name_len = EXFAT_CHARS_PER_NAME_ENTRY;

	if (slot_idx + 3 > entries_per_cluster)
		return (ENOSPC);

	upcase_table = NULL;
	(void)load_upcase_table(ctx, &upcase_table);

	was_eod = (dent[slot_idx].type == EXFAT_ENTRY_EOD ||
	    dent[slot_idx + 1].type == EXFAT_ENTRY_EOD ||
	    dent[slot_idx + 2].type == EXFAT_ENTRY_EOD);
	memset(&dent[slot_idx], 0, sizeof(union exfat_dentry) * 3);

	/* Primary File Entry (Spec §7.4, 0x85) */
	dent[slot_idx].type = EXFAT_ENTRY_FILE;
	dent[slot_idx].file.fe_secondary_count = EXFAT_MIN_SECONDARY_COUNT;
	dent[slot_idx].file.fe_file_attributes = is_dir ?
	    htole16(EXFAT_ATTR_DIRECTORY) : htole16(EXFAT_ATTR_ARCHIVE);

	/* Stream Extension Entry (Spec §7.6, 0xC0) */
	dent[slot_idx + 1].type = EXFAT_ENTRY_STREAM;
	dent[slot_idx + 1].stream.se_general_flags =
	    EXFAT_FLAG_ALLOC_POSSIBLE | EXFAT_FLAG_NO_FAT_CHAIN;
	dent[slot_idx + 1].stream.se_name_length = (uint8_t)name_len;
	dent[slot_idx + 1].stream.se_first_cluster = htole32(first_cn);
	dent[slot_idx + 1].stream.se_data_length =
	    htole64(ctx->cluster_size);
	dent[slot_idx + 1].stream.se_valid_data_length =
	    htole64(ctx->cluster_size);

	/* File Name Entry (Spec §7.7, 0xC1) */
	dent[slot_idx + 2].type = EXFAT_ENTRY_NAME;
	for (size_t c = 0; c < name_len && c < EXFAT_CHARS_PER_NAME_ENTRY;
	    c++) {
		utf16_name[c] = (uint16_t)(uint8_t)sample_name[c];
		dent[slot_idx + 2].name.ne_file_name[c] =
		    htole16(utf16_name[c]);
	}

	/* Compute NameHash per Spec §7.6.4 */
	hash = calc_utf16_name_hash(utf16_name, name_len, upcase_table);
	free(upcase_table);
	dent[slot_idx + 1].stream.se_name_hash = htole16(hash);

	/* SetChecksum (Spec §7.4.3) */
	exfat_dentry_set_checksum(&dent[slot_idx], 3);

	/* Mark next slot as EOD if space permits and this was previously EOD */
	if (was_eod && slot_idx + 3 < entries_per_cluster)
		dent[slot_idx + 3].type = EXFAT_ENTRY_EOD;

	return (0);
}

/*
 * Search for target directory entry set, or populate one if empty.
 */
static int
find_or_create_dentry(struct faultgen_ctx *ctx, const char *target,
    bool is_dir, uint32_t default_first_cn, struct dentry_loc *loc)
{
	uint8_t *cbuf;
	uint32_t avail_cn, clusters_visited, curr_cn;
	size_t entries_per_cluster, file_index, first_avail_slot;
	int error;
	bool hit_eod;

	if (ctx == NULL || loc == NULL)
		return (EINVAL);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	avail_cn = 0;
	clusters_visited = 0;
	file_index = 0;
	first_avail_slot = (size_t)-1;
	hit_eod = false;
	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	curr_cn = ctx->root_dir_cluster;

	while (exfat_cluster_is_valid(curr_cn, ctx->cluster_count)) {
		union exfat_dentry *dentries;
		uint32_t next_cn;

		error = read_cluster(ctx, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		dentries = (union exfat_dentry *)cbuf;
		for (size_t i = 0; i < entries_per_cluster; i++) {
			uint8_t type = dentries[i].type;

			if (type == EXFAT_ENTRY_EOD) {
				if (first_avail_slot == (size_t)-1 &&
				    i + 3 <= entries_per_cluster) {
					first_avail_slot = i;
					avail_cn = curr_cn;
				}
				hit_eod = true;
				break;
			}

			if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
				if (first_avail_slot == (size_t)-1 &&
				    i + 3 <= entries_per_cluster &&
				    (dentries[i + 1].type == EXFAT_ENTRY_EOD ||
				    ((dentries[i + 1].type &
				    EXFAT_ENTRY_TYPE_IN_USE) == 0 &&
				    (dentries[i + 2].type == EXFAT_ENTRY_EOD ||
				    (dentries[i + 2].type &
				    EXFAT_ENTRY_TYPE_IN_USE) == 0)))) {
					first_avail_slot = i;
					avail_cn = curr_cn;
				}
				continue;
			}

			if (type == EXFAT_ENTRY_FILE) {
				uint8_t sec;

				sec = dentries[i].file.fe_secondary_count;
				if (i + 1 + sec <= entries_per_cluster &&
				    dentry_matches_target(&dentries[i], sec,
				    file_index, target)) {
					loc->cluster = curr_cn;
					loc->slot_idx = i;
					loc->cbuf = cbuf;
					return (0);
				}
				file_index++;
				i += sec;
			}
		}

		if (hit_eod)
			break;

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

	/* Not found; create sample entry if an available slot was seen */
	if (first_avail_slot != (size_t)-1) {
		union exfat_dentry *dentries;

		error = read_cluster(ctx, avail_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		dentries = (union exfat_dentry *)cbuf;
		if (!exfat_cluster_is_valid(default_first_cn,
		    ctx->cluster_count))
			default_first_cn = EXFAT_FIRST_CLUSTER;
		error = create_sample_entry(ctx, dentries,
		    first_avail_slot, entries_per_cluster, target,
		    is_dir, default_first_cn);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		loc->cluster = avail_cn;
		loc->slot_idx = first_avail_slot;
		loc->cbuf = cbuf;
		return (0);
	}

	free(cbuf);
	return (ENOENT);
}

/*
 * Write a modified cluster buffer back to disk, free cbuf, and sync the image.
 */
static int
commit_cluster_and_sync(struct faultgen_ctx *ctx, uint32_t cluster,
    uint8_t *cbuf)
{
	int error;

	error = write_cluster(ctx, cluster, cbuf);
	free(cbuf);
	if (error != 0)
		return (error);
	return (sync_image(ctx));
}

/*
 * Corrupt 16-bit SetChecksum of directory entry set (Spec §6.3.3, §7.4.3).
 */
int
fault_dentry_checksum(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint16_t csum;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_create_dentry(ctx, arg, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	csum = le16toh(dentries[loc.slot_idx].file.fe_set_checksum);
	dentries[loc.slot_idx].file.fe_set_checksum = htole16(csum ^ 0x55AA);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Set ValidDataLength > DataLength in stream extension (Spec §7.6.5).
 */
int
fault_stream_vdl_exceeds_dl(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint64_t dl;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_create_dentry(ctx, arg, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < 1 ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM) {
		free(loc.cbuf);
		return (EINVAL);
	}

	dl = le64toh(dentries[loc.slot_idx + 1].stream.se_data_length);
	if (dl > UINT64_MAX - ctx->cluster_size)
		dl = ctx->cluster_size;
	dentries[loc.slot_idx + 1].stream.se_data_length = htole64(dl);
	dentries[loc.slot_idx + 1].stream.se_valid_data_length =
	    htole64(dl + ctx->cluster_size);

	/* Recalculate SetChecksum so the fault is strictly VDL > DL */
	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Set NoFatChain flag on fragmented cluster chain (Spec §6.4.2, §7.6.2).
 */
int
fault_stream_nofatchain_fragment(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint64_t dl;
	uint32_t first_cn, frag_cn;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_create_dentry(ctx, arg, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < 1 ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM) {
		free(loc.cbuf);
		return (EINVAL);
	}

	first_cn = le32toh(dentries[loc.slot_idx + 1].stream.se_first_cluster);
	if (!exfat_cluster_is_valid(first_cn, ctx->cluster_count)) {
		first_cn = ctx->root_dir_cluster + 1;
		if (!exfat_cluster_is_valid(first_cn, ctx->cluster_count))
			first_cn = EXFAT_FIRST_CLUSTER;
		dentries[loc.slot_idx + 1].stream.se_first_cluster =
		    htole32(first_cn);
	}

	dl = ctx->cluster_size * 2;
	dentries[loc.slot_idx + 1].stream.se_data_length = htole64(dl);
	dentries[loc.slot_idx + 1].stream.se_valid_data_length = htole64(dl);

	/* Fragment the FAT chain: link first_cn -> frag_cn */
	if (exfat_cluster_is_valid(first_cn + 2, ctx->cluster_count)) {
		frag_cn = first_cn + 2;
	} else if (first_cn > EXFAT_FIRST_CLUSTER) {
		frag_cn = EXFAT_FIRST_CLUSTER;
	} else if (exfat_cluster_is_valid(first_cn + 1, ctx->cluster_count)) {
		frag_cn = first_cn;
		first_cn = first_cn + 1;
		dentries[loc.slot_idx + 1].stream.se_first_cluster =
		    htole32(first_cn);
	} else {
		free(loc.cbuf);
		return (ENOSPC);
	}

	error = fat_set_all(ctx, first_cn, frag_cn);
	if (error == 0)
		error = fat_set_all(ctx, frag_cn, EXFAT_FAT_EOF);
	if (error != 0) {
		free(loc.cbuf);
		return (error);
	}

	/* Assert NoFatChain despite fragmented allocation */
	dentries[loc.slot_idx + 1].stream.se_general_flags |=
	    (EXFAT_FLAG_NO_FAT_CHAIN | EXFAT_FLAG_ALLOC_POSSIBLE);

	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Create secondary directory entry without primary entry (Spec §6.3, §6.4).
 */
int
fault_dentry_orphaned_secondary(struct faultgen_ctx *ctx, const char *arg)
{
	uint8_t *cbuf;
	union exfat_dentry *dentries;
	size_t entries_per_cluster, slot_idx;
	int error;
	bool was_eod;

	slot_idx = 0;
	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, ctx->root_dir_cluster, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	dentries = (union exfat_dentry *)cbuf;

	if (arg != NULL && *arg != '\0') {
		uint64_t val;

		if (parse_u64_str(arg, NULL, &val) != 0) {
			free(cbuf);
			return (EINVAL);
		}
		if (val >= entries_per_cluster &&
		    val % EXFAT_DENTRY_SIZE == 0)
			val /= EXFAT_DENTRY_SIZE;
		if (val >= entries_per_cluster) {
			free(cbuf);
			return (EINVAL);
		}
		slot_idx = (size_t)val;
	} else {
		/* Search for an unused slot or EOD */
		bool found = false;

		for (size_t i = 0; i < entries_per_cluster; i++) {
			if (dentries[i].type == EXFAT_ENTRY_EOD ||
			    (dentries[i].type & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
				slot_idx = i;
				found = true;
				break;
			}
		}
		if (!found) {
			free(cbuf);
			return (ENOSPC);
		}
	}

	/* Insert an orphaned secondary Stream Extension entry (0xC0) */
	was_eod = (dentries[slot_idx].type == EXFAT_ENTRY_EOD);
	memset(&dentries[slot_idx], 0, sizeof(union exfat_dentry));
	dentries[slot_idx].type = EXFAT_ENTRY_STREAM;
	dentries[slot_idx].stream.se_general_flags = EXFAT_FLAG_ALLOC_POSSIBLE;
	dentries[slot_idx].stream.se_name_length = 8;
	dentries[slot_idx].stream.se_data_length = htole64(ctx->cluster_size);
	dentries[slot_idx].stream.se_valid_data_length =
	    htole64(ctx->cluster_size);

	/* Maintain EOD if this slot was previously EOD */
	if (was_eod && slot_idx + 1 < entries_per_cluster)
		dentries[slot_idx + 1].type = EXFAT_ENTRY_EOD;

	error = write_cluster(ctx, ctx->root_dir_cluster, cbuf);
	free(cbuf);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Create invalid directory pointer back to root (Spec §6.3).
 */
int
fault_dentry_root_in_subdir(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_create_dentry(ctx, arg, true, ctx->root_dir_cluster,
	    &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < 1 ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM) {
		free(loc.cbuf);
		return (EINVAL);
	}

	/* Set Directory attribute */
	dentries[loc.slot_idx].file.fe_file_attributes |=
	    htole16(EXFAT_ATTR_DIRECTORY);

	/* Point first cluster back to root directory cluster */
	dentries[loc.slot_idx + 1].stream.se_first_cluster =
	    htole32(ctx->root_dir_cluster);

	/* Ensure stream lengths are valid */
	if (le64toh(dentries[loc.slot_idx + 1].stream.se_data_length) == 0) {
		dentries[loc.slot_idx + 1].stream.se_data_length =
		    htole64(ctx->cluster_size);
		dentries[loc.slot_idx + 1].stream.se_valid_data_length =
		    htole64(ctx->cluster_size);
	}

	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Corrupt SecondaryCount in File directory entry (Spec §7.4.2).
 *
 * SecondaryCount must be in the range [2, 18] and match the count of
 * following secondary entries (at least 1 Stream Extension and 1 File Name
 * entry).  Recalculates SetChecksum across available entries to isolate
 * the structural SecondaryCount defect.
 */
int
fault_dentry_secondary_count(struct faultgen_ctx *ctx, const char *arg)
{
	char target[EXFAT_MAX_NAME_CHARS + 1];
	const char *param;
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	size_t count_limit, entries_per_cluster;
	uint8_t new_sec, old_sec;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	parse_target_and_param(arg, target, sizeof(target), &param);

	error = find_or_create_dentry(ctx, target, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	old_sec = dentries[loc.slot_idx].file.fe_secondary_count;

	if (param != NULL) {
		uint32_t val;

		if (parse_u32_str(param, NULL, &val) != 0 || val > 255) {
			free(loc.cbuf);
			return (EINVAL);
		}
		new_sec = (uint8_t)val;
	} else {
		/*
		 * Default mutation: if SecondaryCount >= 2, corrupt to 1
		 * (violates Spec §7.4.2 minimum count of 2); otherwise
		 * invert low bit.
		 */
		new_sec = (old_sec >= EXFAT_MIN_SECONDARY_COUNT) ?
		    (old_sec == EXFAT_MIN_SECONDARY_COUNT ? 1 : old_sec - 1) :
		    (old_sec + 1);
	}

	dentries[loc.slot_idx].file.fe_secondary_count = new_sec;

	/*
	 * Recompute SetChecksum (Spec §7.4.3). Clamp count to remaining
	 * slots in cluster buffer to prevent buffer over-read if an
	 * out-of-range secondary count was injected.
	 */
	count_limit = 1 + (size_t)new_sec;
	if (loc.slot_idx + count_limit > entries_per_cluster)
		count_limit = entries_per_cluster - loc.slot_idx;
	exfat_dentry_set_checksum(&dentries[loc.slot_idx], count_limit);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Corrupt NameHash in Stream Extension entry (Spec §7.6.4).
 *
 * Mutates the 16-bit NameHash while recalculating SetChecksum (Spec §7.4.3)
 * across the directory entry set, isolating the NameHash mismatch defect.
 */
int
fault_dentry_name_hash(struct faultgen_ctx *ctx, const char *arg)
{
	char target[EXFAT_MAX_NAME_CHARS + 1];
	const char *param;
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint16_t new_hash, old_hash;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	parse_target_and_param(arg, target, sizeof(target), &param);

	error = find_or_create_dentry(ctx, target, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < 1 ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM) {
		free(loc.cbuf);
		return (EINVAL);
	}

	if (param != NULL) {
		uint32_t val;

		if (parse_u32_str(param, NULL, &val) != 0 || val > 0xFFFF) {
			free(loc.cbuf);
			return (EINVAL);
		}
		new_hash = (uint16_t)val;
	} else {
		old_hash = le16toh(
		    dentries[loc.slot_idx + 1].stream.se_name_hash);
		new_hash = (old_hash == 0) ? 0x55AA : (old_hash ^ 0x55AA);
	}

	dentries[loc.slot_idx + 1].stream.se_name_hash = htole16(new_hash);
	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Inject forbidden characters into File Name entries (Spec §7.7.3).
 *
 * Injects invalid Unicode characters (< 0x0020 or ", *, /, :, <, >, ?, \, |)
 * into the primary File Name entry while recalculating SetChecksum (Spec
 * §7.4.3), isolating the filename character validation defect.
 */
int
fault_dentry_invalid_name_chars(struct faultgen_ctx *ctx, const char *arg)
{
	char target[EXFAT_MAX_NAME_CHARS + 1];
	const char *param;
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint16_t utf16_name[EXFAT_MAX_NAME_CHARS + 1];
	uint16_t *upcase_table;
	size_t name_chars;
	uint16_t bad_char, hash;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	parse_target_and_param(arg, target, sizeof(target), &param);

	error = find_or_create_dentry(ctx, target, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM ||
	    dentries[loc.slot_idx + 2].type != EXFAT_ENTRY_NAME) {
		free(loc.cbuf);
		return (EINVAL);
	}

	if (param != NULL) {
		char *endp;
		unsigned long val;

		val = strtoul(param, &endp, 0);
		if (*endp == '\0') {
			if (val > 0xFFFF) {
				free(loc.cbuf);
				return (EINVAL);
			}
			bad_char = (uint16_t)val;
		} else if (param[0] != '\0' && param[1] == '\0') {
			bad_char = (uint16_t)(uint8_t)param[0];
		} else {
			free(loc.cbuf);
			return (EINVAL);
		}
	} else {
		/* Default to colon (':', 0x003A), forbidden per Spec §7.7.3 */
		bad_char = (uint16_t)':';
	}

	dentries[loc.slot_idx + 2].name.ne_file_name[0] = htole16(bad_char);

	/*
	 * Recompute NameHash (Spec §7.6.4) so the fault is strictly an
	 * invalid filename character rather than also a NameHash mismatch.
	 */
	upcase_table = NULL;
	(void)load_upcase_table(ctx, &upcase_table);
	name_chars = extract_dentry_utf16(&dentries[loc.slot_idx], sec_count,
	    utf16_name, nitems(utf16_name));
	hash = calc_utf16_name_hash(utf16_name, name_chars, upcase_table);
	free(upcase_table);
	dentries[loc.slot_idx + 1].stream.se_name_hash = htole16(hash);
	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Set DataLength/ValidDataLength mismatching FAT chain size (Spec §7.6.5,
 * §7.6.7).
 *
 * Modifies Stream Extension DataLength and ValidDataLength to create a
 * discrepancy with the allocated cluster chain in the FAT, while recalculating
 * SetChecksum (Spec §7.4.3) to isolate the cluster allocation defect.
 */
int
fault_dentry_size_mismatch(struct faultgen_ctx *ctx, const char *arg)
{
	char target[EXFAT_MAX_NAME_CHARS + 1];
	const char *param;
	struct dentry_loc loc;
	union exfat_dentry *dentries;
	uint64_t new_dl, old_dl;
	uint32_t first_cn;
	uint8_t sec_count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	parse_target_and_param(arg, target, sizeof(target), &param);

	error = find_or_create_dentry(ctx, target, false,
	    ctx->root_dir_cluster + 1, &loc);
	if (error != 0)
		return (error);

	dentries = (union exfat_dentry *)loc.cbuf;
	sec_count = dentries[loc.slot_idx].file.fe_secondary_count;
	if (sec_count < 1 ||
	    dentries[loc.slot_idx + 1].type != EXFAT_ENTRY_STREAM) {
		free(loc.cbuf);
		return (EINVAL);
	}

	old_dl = le64toh(dentries[loc.slot_idx + 1].stream.se_data_length);

	if (param != NULL) {
		if (parse_u64_str(param, NULL, &new_dl) != 0) {
			free(loc.cbuf);
			return (EINVAL);
		}
	} else {
		/*
		 * Discrepancy: exceed allocated cluster chain by 2 clusters
		 * so DataLength requires more clusters than allocated in FAT.
		 */
		new_dl = old_dl + (uint64_t)ctx->cluster_size * 2;
		if (new_dl == 0)
			new_dl = (uint64_t)ctx->cluster_size * 2;
	}

	/*
	 * Clear NoFatChain flag so stream uses the FAT chain, and ensure
	 * the starting cluster is terminated with EOF if unlinked.
	 */
	first_cn = le32toh(dentries[loc.slot_idx + 1].stream.se_first_cluster);
	if (exfat_cluster_is_valid(first_cn, ctx->cluster_count)) {
		uint32_t val;

		if (fat_get(ctx, first_cn, &val) == 0 &&
		    val == EXFAT_FAT_FREE) {
			error = fat_set_all(ctx, first_cn, EXFAT_FAT_EOF);
			if (error != 0) {
				free(loc.cbuf);
				return (error);
			}
		}
	}
	dentries[loc.slot_idx + 1].stream.se_general_flags &=
	    ~EXFAT_FLAG_NO_FAT_CHAIN;

	dentries[loc.slot_idx + 1].stream.se_data_length = htole64(new_dl);
	dentries[loc.slot_idx + 1].stream.se_valid_data_length =
	    htole64(new_dl);
	exfat_dentry_set_checksum(&dentries[loc.slot_idx], 1 + sec_count);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Invert or corrupt TableChecksum in Up-case Table directory entry
 * (Spec §7.2.2).
 */
int
fault_upcase_checksum_mismatch(struct faultgen_ctx *ctx, const char *arg)
{
	struct upcase_info info;
	uint8_t *cbuf;
	union exfat_dentry *dent;
	uint32_t new_csum;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = upcase_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		if (parse_u32_str(arg, NULL, &new_csum) != 0)
			return (EINVAL);
	} else
		new_csum = info.table_checksum ^ 0xFFFFFFFFU;

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	error = read_cluster(ctx, info.dentry_cluster, cbuf);
	if (error != 0) {
		free(cbuf);
		return (error);
	}

	dent = (union exfat_dentry *)(cbuf + info.dentry_offset);
	dent->upcase.uc_table_checksum = htole32(new_csum);

	if (ctx->verbose)
		printf("Corrupted Up-case TableChecksum: 0x%08" PRIX32
		    " -> 0x%08" PRIX32 "\n", info.table_checksum, new_csum);

	error = write_cluster(ctx, info.dentry_cluster, cbuf);
	free(cbuf);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Truncate Up-case Table DataLength or cluster chain (Spec §7.2.4).
 */
int
fault_upcase_truncate(struct faultgen_ctx *ctx, const char *arg)
{
	struct upcase_info info;
	uint8_t *cbuf;
	union exfat_dentry *dent;
	uint64_t new_len;
	bool truncate_chain;
	int error;

	truncate_chain = false;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = upcase_find_entry(ctx, &info);
	if (error != 0)
		return (error);

	if (arg != NULL && strcmp(arg, "chain") == 0) {
		truncate_chain = true;
		new_len = info.data_length;
	} else if (arg != NULL && *arg != '\0') {
		if (parse_u64_str(arg, NULL, &new_len) != 0)
			return (EINVAL);
	} else {
		new_len = (info.data_length > 2) ? 2 : 0;
		truncate_chain = true;
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
	dent->upcase.uc_data_length = htole64(new_len);

	if (ctx->verbose)
		printf("Truncated Up-case DataLength: %" PRIu64 " -> %" PRIu64
		    " bytes%s\n", info.data_length, new_len,
		    truncate_chain ? " (with FAT chain truncation)" : "");

	error = write_cluster(ctx, info.dentry_cluster, cbuf);
	free(cbuf);
	if (error != 0)
		return (error);

	if (truncate_chain &&
	    exfat_cluster_is_valid(info.first_cluster, ctx->cluster_count)) {
		error = fat_set_all(ctx, info.first_cluster, EXFAT_FAT_EOF);
		if (error != 0)
			return (error);
	}

	return (sync_image(ctx));
}

/*
 * Find an entry of the specified type in the root directory.
 */
static int
find_root_entry_by_type(struct faultgen_ctx *ctx, uint8_t target_type,
    struct dentry_loc *loc)
{
	uint8_t *cbuf;
	uint32_t clusters_visited, curr_cn;
	size_t entries_per_cluster;
	int error;

	if (ctx == NULL || loc == NULL)
		return (EINVAL);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	clusters_visited = 0;
	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	curr_cn = ctx->root_dir_cluster;

	while (exfat_cluster_is_valid(curr_cn, ctx->cluster_count)) {
		union exfat_dentry *dentries;
		uint32_t next_cn;

		error = read_cluster(ctx, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		dentries = (union exfat_dentry *)cbuf;
		for (size_t i = 0; i < entries_per_cluster; i++) {
			if (dentries[i].type == EXFAT_ENTRY_EOD) {
				free(cbuf);
				return (ENOENT);
			}
			if (dentries[i].type == target_type) {
				loc->cluster = curr_cn;
				loc->slot_idx = i;
				loc->cbuf = cbuf;
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
 * Find an available single slot in the root directory.
 */
static int
find_root_available_slot(struct faultgen_ctx *ctx, uint32_t skip_cluster,
    size_t skip_slot, struct dentry_loc *loc)
{
	uint8_t *cbuf;
	uint32_t clusters_visited, curr_cn;
	size_t entries_per_cluster;
	int error;

	if (ctx == NULL || loc == NULL)
		return (EINVAL);

	cbuf = malloc(ctx->cluster_size);
	if (cbuf == NULL)
		return (ENOMEM);

	clusters_visited = 0;
	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	curr_cn = ctx->root_dir_cluster;

	while (exfat_cluster_is_valid(curr_cn, ctx->cluster_count)) {
		union exfat_dentry *dentries;
		uint32_t next_cn;

		error = read_cluster(ctx, curr_cn, cbuf);
		if (error != 0) {
			free(cbuf);
			return (error);
		}

		dentries = (union exfat_dentry *)cbuf;
		for (size_t i = 0; i < entries_per_cluster; i++) {
			if (curr_cn == skip_cluster && i == skip_slot)
				continue;

			if (dentries[i].type == EXFAT_ENTRY_EOD ||
			    (dentries[i].type & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
				loc->cluster = curr_cn;
				loc->slot_idx = i;
				loc->cbuf = cbuf;
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
	return (ENOSPC);
}

/*
 * Write a single root directory entry preserving EOD sentinel if applicable.
 */
static void
write_single_root_dentry(union exfat_dentry *dentries, size_t slot_idx,
    size_t entries_per_cluster, const union exfat_dentry *new_dent)
{
	bool was_eod = (dentries[slot_idx].type == EXFAT_ENTRY_EOD);

	dentries[slot_idx] = *new_dent;
	if (was_eod && slot_idx + 1 < entries_per_cluster)
		dentries[slot_idx + 1].type = EXFAT_ENTRY_EOD;
}

/*
 * Inject duplicate Volume Label directory entry into root directory
 * (Spec §7.3.1).
 */
int
fault_label_duplicate(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc dup_loc, loc;
	union exfat_dentry label_entry;
	size_t entries_per_cluster;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);

	memset(&label_entry, 0, sizeof(label_entry));
	label_entry.type = EXFAT_ENTRY_VOLUME_LABEL;

	error = find_root_entry_by_type(ctx, EXFAT_ENTRY_VOLUME_LABEL, &loc);
	if (error == 0) {
		union exfat_dentry *dentries =
		    (union exfat_dentry *)loc.cbuf;

		label_entry = dentries[loc.slot_idx];

		if (arg != NULL && *arg != '\0') {
			size_t len = strlen(arg);

			if (len > EXFAT_MAX_VOLUME_LABEL_CHARS)
				len = EXFAT_MAX_VOLUME_LABEL_CHARS;
			label_entry.volume_label.vl_character_count =
			    (uint8_t)len;
			memset(label_entry.volume_label.vl_volume_label, 0,
			    sizeof(label_entry.volume_label.vl_volume_label));
			for (size_t c = 0; c < len; c++)
				label_entry.volume_label.vl_volume_label[c] =
				    htole16((uint16_t)(uint8_t)arg[c]);
		}

		error = find_root_available_slot(ctx, loc.cluster, loc.slot_idx,
		    &dup_loc);
		free(loc.cbuf);
		if (error != 0)
			return (error);
	} else {
		const char *lbl = (arg != NULL && *arg != '\0') ?
		    arg : "DUPLABEL";
		size_t len = strlen(lbl);

		if (len > EXFAT_MAX_VOLUME_LABEL_CHARS)
			len = EXFAT_MAX_VOLUME_LABEL_CHARS;

		label_entry.volume_label.vl_character_count = (uint8_t)len;
		for (size_t c = 0; c < len; c++)
			label_entry.volume_label.vl_volume_label[c] =
			    htole16((uint16_t)(uint8_t)lbl[c]);

		error = find_root_available_slot(ctx, 0, (size_t)-1, &loc);
		if (error != 0)
			return (error);

		write_single_root_dentry((union exfat_dentry *)loc.cbuf,
		    loc.slot_idx, entries_per_cluster, &label_entry);
		error = write_cluster(ctx, loc.cluster, loc.cbuf);
		if (error != 0) {
			free(loc.cbuf);
			return (error);
		}

		error = find_root_available_slot(ctx, loc.cluster, loc.slot_idx,
		    &dup_loc);
		free(loc.cbuf);
		if (error != 0)
			return (error);
	}

	write_single_root_dentry((union exfat_dentry *)dup_loc.cbuf,
	    dup_loc.slot_idx, entries_per_cluster, &label_entry);
	return (commit_cluster_and_sync(ctx, dup_loc.cluster, dup_loc.cbuf));
}

/*
 * Find an existing root directory entry of target_type, or allocate and
 * initialize a new slot while preserving the EOD sentinel.
 */
static int
find_or_alloc_root_entry(struct faultgen_ctx *ctx, uint8_t target_type,
    struct dentry_loc *loc, bool *created_out)
{
	union exfat_dentry *dent;
	size_t entries_per_cluster;
	int error;
	bool was_eod;

	if (created_out != NULL)
		*created_out = false;

	error = find_root_entry_by_type(ctx, target_type, loc);
	if (error == 0)
		return (0);

	error = find_root_available_slot(ctx, 0, (size_t)-1, loc);
	if (error != 0)
		return (error);

	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);
	dent = (union exfat_dentry *)loc->cbuf + loc->slot_idx;
	was_eod = (dent->type == EXFAT_ENTRY_EOD);
	memset(dent, 0, sizeof(*dent));
	dent->type = target_type;
	if (was_eod && loc->slot_idx + 1 < entries_per_cluster)
		dent[1].type = EXFAT_ENTRY_EOD;
	if (created_out != NULL)
		*created_out = true;

	return (0);
}

/*
 * Inject forbidden characters into Volume Label (Spec §7.3.3).
 */
int
fault_label_invalid_chars(struct faultgen_ctx *ctx, const char *arg)
{
	uint16_t label_chars[EXFAT_MAX_VOLUME_LABEL_CHARS];
	struct dentry_loc loc;
	union exfat_dentry *dent;
	const char *lbl;
	size_t len;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_alloc_root_entry(ctx, EXFAT_ENTRY_VOLUME_LABEL, &loc,
	    NULL);
	if (error != 0)
		return (error);
	dent = (union exfat_dentry *)loc.cbuf + loc.slot_idx;

	lbl = (arg != NULL && *arg != '\0') ? arg : "BAD/LABEL";
	len = strlen(lbl);
	if (len > EXFAT_MAX_VOLUME_LABEL_CHARS)
		len = EXFAT_MAX_VOLUME_LABEL_CHARS;

	dent->volume_label.vl_character_count = (uint8_t)len;
	memset(dent->volume_label.vl_volume_label, 0,
	    sizeof(dent->volume_label.vl_volume_label));
	for (size_t c = 0; c < len; c++)
		dent->volume_label.vl_volume_label[c] =
		    htole16((uint16_t)(uint8_t)lbl[c]);

	for (size_t k = 0; k < EXFAT_MAX_VOLUME_LABEL_CHARS; k++)
		label_chars[k] = le16toh(dent->volume_label.vl_volume_label[k]);
	if (is_valid_volume_label(label_chars, len)) {
		dent->volume_label.vl_volume_label[0] = htole16('/');
		if (len == 0)
			dent->volume_label.vl_character_count = 1;
	}

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Set CharacterCount > 11 in Volume Label entry (Spec §7.3.2).
 */
int
fault_label_length(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dent;
	uint8_t count;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) == 0) {
			if (val > 255)
				return (EINVAL);
			count = (uint8_t)val;
		} else {
			size_t len;

			len = strlen(arg);
			if (len > 255)
				return (EINVAL);
			count = (uint8_t)len;
		}
	} else
		count = 12;

	error = find_or_alloc_root_entry(ctx, EXFAT_ENTRY_VOLUME_LABEL, &loc,
	    NULL);
	if (error != 0)
		return (error);
	dent = (union exfat_dentry *)loc.cbuf + loc.slot_idx;

	dent->volume_label.vl_character_count = count;
	for (size_t c = 0; c < EXFAT_MAX_VOLUME_LABEL_CHARS; c++)
		dent->volume_label.vl_volume_label[c] =
		    htole16((uint16_t)('A' + (c % 26)));

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}

/*
 * Inject duplicate Volume GUID directory entry into root directory
 * (Spec §7.5.1).
 */
int
fault_guid_duplicate(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc dup_loc, loc;
	union exfat_dentry guid_entry;
	size_t entries_per_cluster;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	entries_per_cluster = ctx->cluster_size / sizeof(union exfat_dentry);

	memset(&guid_entry, 0, sizeof(guid_entry));
	guid_entry.type = EXFAT_ENTRY_VOLUME_GUID;

	error = find_root_entry_by_type(ctx, EXFAT_ENTRY_VOLUME_GUID, &loc);
	if (error == 0) {
		union exfat_dentry *dentries =
		    (union exfat_dentry *)loc.cbuf;

		guid_entry = dentries[loc.slot_idx];

		if (arg != NULL && *arg != '\0') {
			error = parse_guid(arg,
			    guid_entry.volume_guid.vg_guid);
			if (error != 0) {
				free(loc.cbuf);
				return (error);
			}
		}

		exfat_dentry_set_checksum(&guid_entry, 1);

		error = find_root_available_slot(ctx, loc.cluster, loc.slot_idx,
		    &dup_loc);
		free(loc.cbuf);
		if (error != 0)
			return (error);
	} else {
		if (arg != NULL && *arg != '\0') {
			error = parse_guid(arg,
			    guid_entry.volume_guid.vg_guid);
			if (error != 0)
				return (error);
		} else {
			static const uint8_t sample_guid[16] = {
				0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
			};

			memcpy(guid_entry.volume_guid.vg_guid, sample_guid, 16);
		}
		exfat_dentry_set_checksum(&guid_entry, 1);

		error = find_root_available_slot(ctx, 0, (size_t)-1, &loc);
		if (error != 0)
			return (error);

		write_single_root_dentry((union exfat_dentry *)loc.cbuf,
		    loc.slot_idx, entries_per_cluster, &guid_entry);
		error = write_cluster(ctx, loc.cluster, loc.cbuf);
		if (error != 0) {
			free(loc.cbuf);
			return (error);
		}

		error = find_root_available_slot(ctx, loc.cluster, loc.slot_idx,
		    &dup_loc);
		free(loc.cbuf);
		if (error != 0)
			return (error);
	}

	write_single_root_dentry((union exfat_dentry *)dup_loc.cbuf,
	    dup_loc.slot_idx, entries_per_cluster, &guid_entry);
	return (commit_cluster_and_sync(ctx, dup_loc.cluster, dup_loc.cbuf));
}

/*
 * Set non-zero SecondaryCount or GeneralPrimaryFlags in Volume GUID entry
 * (Spec §7.5.2, §7.5.4).
 */
int
fault_guid_invalid(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_loc loc;
	union exfat_dentry *dent;
	int error;
	bool created;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = find_or_alloc_root_entry(ctx, EXFAT_ENTRY_VOLUME_GUID, &loc,
	    &created);
	if (error != 0)
		return (error);
	dent = (union exfat_dentry *)loc.cbuf + loc.slot_idx;
	if (created) {
		static const uint8_t sample_guid[16] = {
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
		};

		memcpy(dent->volume_guid.vg_guid, sample_guid, 16);
	}

	if (arg != NULL && (strcasecmp(arg, "flags") == 0 ||
	    strcasecmp(arg, "general_flags") == 0)) {
		dent->volume_guid.vg_general_flags = htole16(0x0001);
	} else if (arg != NULL && (strcasecmp(arg, "count") == 0 ||
	    strcasecmp(arg, "secondary") == 0 ||
	    strcasecmp(arg, "secondary_count") == 0)) {
		dent->volume_guid.vg_secondary_count = 1;
	} else if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) != 0 || val == 0 ||
		    val > 0xFF) {
			free(loc.cbuf);
			return (EINVAL);
		}
		dent->volume_guid.vg_secondary_count = (uint8_t)val;
		dent->volume_guid.vg_general_flags = htole16((uint16_t)val);
	} else {
		dent->volume_guid.vg_secondary_count = 1;
		dent->volume_guid.vg_general_flags = htole16(0x0001);
	}

	exfat_dentry_set_checksum(dent, 1);

	return (commit_cluster_and_sync(ctx, loc.cluster, loc.cbuf));
}
