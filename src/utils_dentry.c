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
#include <strings.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

struct dir_item {
	uint32_t	cluster;
	bool		no_fat_chain;
	uint64_t	data_len;
	char		path[1024];
};

struct dir_queue {
	struct dir_item	*items;
	size_t		head;
	size_t		tail;
	size_t		capacity;
};

static int	decompress_upcase(const uint8_t *raw, size_t raw_len,
		    uint16_t *table);
static int	queue_init(struct dir_queue *q);
static void	queue_free(struct dir_queue *q);
static int	queue_enqueue(struct dir_queue *q, uint32_t cluster,
		    bool no_fat_chain, uint64_t data_len, const char *path);
static bool	queue_dequeue(struct dir_queue *q, struct dir_item *item);
static bool	is_valid_utc_offset(uint8_t val);
static bool	is_valid_timestamp(uint32_t ts);
static void	format_dos_timestamp(uint32_t ts, uint8_t ms10, uint8_t tz,
		    char *buf, size_t size);
static void	format_attributes(uint16_t attr, char *buf, size_t size);
static void	format_stream_flags(uint8_t flags, char *buf, size_t size);
static int	load_directory_clusters(struct faultgen_ctx *ctx,
		    uint32_t first_cn, bool no_fat_chain, uint64_t data_len,
		    uint8_t *visited_bitmap, bool *chain_bad,
		    uint8_t **out_buf, size_t *out_slots);
static size_t	dump_file_entry_set(struct faultgen_ctx *ctx,
		    const union exfat_dentry *dentries, size_t s,
		    size_t total_slots, const char *dir_path,
		    const char *target, bool match_dir,
		    struct dentry_stats *stats, struct dir_queue *queue,
		    uint8_t *visited_bitmap, const uint16_t *upcase_table,
		    bool *target_found, bool verbose);
static int	dump_single_directory(struct faultgen_ctx *ctx,
		    uint32_t first_cn, const char *dir_path, bool no_fat_chain,
		    uint64_t data_len, const char *target,
		    struct dentry_stats *stats, struct dir_queue *queue,
		    uint8_t *visited_bitmap, const uint16_t *upcase_table,
		    bool *target_found, bool verbose);
static void	verify_bitmap_entry(struct faultgen_ctx *ctx,
		    const struct exfat_dentry_bitmap *bm,
		    struct dentry_stats *stats, uint32_t first_cn,
		    bool *seen_bm0, bool *seen_bm1, bool print_all, size_t s);
static void	verify_upcase_entry(struct faultgen_ctx *ctx,
		    const struct exfat_dentry_upcase *uc,
		    struct dentry_stats *stats, uint32_t first_cn,
		    bool print_all, size_t s);
static void	verify_volume_label_entry(struct faultgen_ctx *ctx,
		    const struct exfat_dentry_volume_label *vl,
		    struct dentry_stats *stats, uint32_t first_cn,
		    bool print_all, size_t s);
static void	verify_volume_guid_entry(struct faultgen_ctx *ctx,
		    const union exfat_dentry *dent,
		    struct dentry_stats *stats, uint32_t first_cn,
		    bool print_all, size_t s);
static int	read_upcase_data(struct faultgen_ctx *ctx, uint32_t first_cn,
		    size_t data_len, uint8_t **buf_out, uint32_t *last_cn_out);
static bool	is_valid_file_name(const uint16_t *name, size_t nchars);
static void	print_dentry_summary(const struct dentry_stats *stats);

/*
 * Initialize directory traversal queue.
 */
static int
queue_init(struct dir_queue *q)
{
	q->capacity = 64;
	q->head = 0;
	q->tail = 0;
	q->items = malloc(q->capacity * sizeof(*q->items));
	if (q->items == NULL)
		return (ENOMEM);
	return (0);
}

/*
 * Free directory traversal queue.
 */
static void
queue_free(struct dir_queue *q)
{
	if (q->items != NULL) {
		free(q->items);
		q->items = NULL;
	}
	q->head = 0;
	q->tail = 0;
	q->capacity = 0;
}

/*
 * Enqueue directory item for traversal.
 */
static int
queue_enqueue(struct dir_queue *q, uint32_t cluster, bool no_fat_chain,
    uint64_t data_len, const char *path)
{
	if (q->tail >= q->capacity) {
		size_t new_cap = q->capacity * 2;
		struct dir_item *new_items;

		new_items = realloc(q->items,
		    new_cap * sizeof(struct dir_item));
		if (new_items == NULL)
			return (ENOMEM);
		q->items = new_items;
		q->capacity = new_cap;
	}

	q->items[q->tail].cluster = cluster;
	q->items[q->tail].no_fat_chain = no_fat_chain;
	q->items[q->tail].data_len = data_len;
	strlcpy(q->items[q->tail].path, path, sizeof(q->items[q->tail].path));
	q->tail++;
	return (0);
}

/*
 * Dequeue next directory item.
 */
static bool
queue_dequeue(struct dir_queue *q, struct dir_item *item)
{
	if (q->head >= q->tail)
		return (false);
	*item = q->items[q->head++];
	return (true);
}

/*
 * Validate UTC offset field per Spec §7.4.10.
 *
 * Per Spec §7.4.10.1 (Table 31) and §7.4.10.2, when OffsetValid (bit 7) is 1,
 * bits 0-6 form a 7-bit signed two's-complement integer representing the
 * offset from UTC in 15-minute intervals, and all 7-bit values from -64
 * (40h, UTC-16:00) through +63 (3Fh, UTC+15:45) are valid.  When OffsetValid
 * (bit 7) is 0, no UTC offset is valid and the entire field must be 0x00.
 */
static bool
is_valid_utc_offset(uint8_t val)
{
	if ((val & EXFAT_TZ_VALID) == 0)
		return (val == 0);

	return (true);
}

/*
 * Validate MS-DOS 32-bit date and time format per Spec §7.4.8.
 *
 * Verifies DoubleSeconds (bits 0-4, range 0-29), Minute (bits 5-10, range
 * 0-59), Hour (bits 11-15, range 0-23), Day (bits 16-20, range 1-31),
 * Month (bits 21-24, range 1-12), and Year (bits 25-31, offset from 1980).
 * A timestamp of 0 represents unset/epoch.
 */
static bool
is_valid_timestamp(uint32_t ts)
{
	uint32_t day, hour, min, month, sec2;

	if (ts == 0)
		return (true);

	sec2 = ts & 0x1F;
	min = (ts >> 5) & 0x3F;
	hour = (ts >> 11) & 0x1F;
	day = (ts >> 16) & 0x1F;
	month = (ts >> 21) & 0x0F;

	return (sec2 <= 29 && min <= 59 && hour <= 23 &&
	    day >= 1 && day <= 31 && month >= 1 && month <= 12);
}

/*
 * Format MS-DOS packed timestamp and timezone per Spec §7.4.8 - §7.4.10.
 */
static void
format_dos_timestamp(uint32_t ts, uint8_t ms10, uint8_t tz, char *buf,
    size_t size)
{
	unsigned int day, hour, minute, month, second, year;
	int tz_hours, tz_mins;
	int8_t tz_offset;
	char tz_str[32];

	if (ts == 0) {
		snprintf(buf, size, "<none>");
		return;
	}

	second = (ts & 0x1F) * 2 + (ms10 / 100);
	minute = (ts >> 5) & 0x3F;
	hour = (ts >> 11) & 0x1F;
	day = (ts >> 16) & 0x1F;
	month = (ts >> 21) & 0x0F;
	year = ((ts >> 25) & 0x7F) + 1980;

	if ((tz & EXFAT_TZ_VALID) != 0) {
		/*
		 * Bits 0-6 form a 7-bit signed two's-complement integer per
		 * Spec §7.4.10.  Bit 6 (0x40) is its 7-bit sign bit.  Sign-
		 * extend into bit 7 (0x80) so int8_t represents the negative
		 * value properly in memory.
		 */
		tz_offset = (int8_t)(tz & EXFAT_TZ_OFFSET_MASK);
		if ((tz_offset & 0x40) != 0)
			tz_offset |= (int8_t)0x80;
		tz_hours = abs(tz_offset) / 4;
		tz_mins = (abs(tz_offset) % 4) * 15;
		snprintf(tz_str, sizeof(tz_str), " (UTC%c%02d:%02d)",
		    (tz_offset < 0) ? '-' : '+', tz_hours, tz_mins);
	} else
		tz_str[0] = '\0';

	snprintf(buf, size, "%04u-%02u-%02u %02u:%02u:%02u%s",
	    year, month, day, hour, minute, second, tz_str);
}

/*
 * Format file attributes bitmask per Spec §7.4.4.
 */
static void
format_attributes(uint16_t attr, char *buf, size_t size)
{
	char parts[128];
	size_t len;

	parts[0] = '\0';
	if ((attr & EXFAT_ATTR_DIRECTORY) != 0)
		strlcat(parts, "Directory, ", sizeof(parts));
	if ((attr & EXFAT_ATTR_ARCHIVE) != 0)
		strlcat(parts, "Archive, ", sizeof(parts));
	if ((attr & EXFAT_ATTR_READ_ONLY) != 0)
		strlcat(parts, "Read-Only, ", sizeof(parts));
	if ((attr & EXFAT_ATTR_HIDDEN) != 0)
		strlcat(parts, "Hidden, ", sizeof(parts));
	if ((attr & EXFAT_ATTR_SYSTEM) != 0)
		strlcat(parts, "System, ", sizeof(parts));

	if (parts[0] != '\0') {
		len = strlen(parts);
		if (len >= 2)
			parts[len - 2] = '\0';
		snprintf(buf, size, "0x%04" PRIX16 " [%s]", attr, parts);
	} else
		snprintf(buf, size, "0x%04" PRIX16 " [None]", attr);
}

/*
 * Format stream extension general secondary flags per Spec §7.6.2.
 */
static void
format_stream_flags(uint8_t flags, char *buf, size_t size)
{
	char parts[128];
	size_t len;

	parts[0] = '\0';
	if ((flags & EXFAT_FLAG_ALLOC_POSSIBLE) != 0)
		strlcat(parts, "AllocationPossible, ", sizeof(parts));
	if ((flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0)
		strlcat(parts, "NoFatChain, ", sizeof(parts));

	if (parts[0] != '\0') {
		len = strlen(parts);
		if (len >= 2)
			parts[len - 2] = '\0';
		snprintf(buf, size, "0x%02" PRIX8 " [%s]", flags, parts);
	} else
		snprintf(buf, size, "0x%02" PRIX8 " [None]", flags);
}

/*
 * Read directory clusters into a single contiguous buffer (Spec §6.3, §6.4).
 */
static int
load_directory_clusters(struct faultgen_ctx *ctx, uint32_t first_cn,
    bool no_fat_chain, uint64_t data_len, uint8_t *visited_bitmap,
    bool *chain_bad, uint8_t **out_buf, size_t *out_slots)
{
	uint8_t *buf = NULL, *local_visited = NULL;
	uint32_t curr_cn = first_cn;
	size_t max_clusters, num_clusters = 0;
	int error;

	if (chain_bad != NULL)
		*chain_bad = false;
	if (!exfat_cluster_is_valid(first_cn, ctx->cluster_count))
		return (EINVAL);

	max_clusters = EXFAT_MAX_DIR_SIZE / ctx->cluster_size;
	if (max_clusters > ctx->cluster_count)
		max_clusters = ctx->cluster_count;

	if (no_fat_chain && data_len > 0) {
		if (data_len > EXFAT_MAX_DIR_SIZE)
			data_len = EXFAT_MAX_DIR_SIZE;
		num_clusters = howmany(data_len, ctx->cluster_size);
		if (num_clusters > max_clusters)
			num_clusters = max_clusters;
		buf = malloc(num_clusters * ctx->cluster_size);
		if (buf == NULL)
			return (ENOMEM);
		for (size_t i = 0; i < num_clusters; i++) {
			uint64_t cn64 = (uint64_t)first_cn + i;
			uint32_t cn;

			if (cn64 > UINT32_MAX ||
			    !exfat_cluster_is_valid((uint32_t)cn64,
			    ctx->cluster_count)) {
				free(buf);
				return (EINVAL);
			}
			cn = (uint32_t)cn64;
			if (visited_bitmap != NULL) {
				uint32_t idx = EXFAT_CNTOI(cn);

				visited_bitmap[idx / 8] |=
				    (uint8_t)(1U << (idx % 8));
			}
			error = read_cluster(ctx, cn,
			    buf + (i * ctx->cluster_size));
			if (error != 0) {
				free(buf);
				return (error);
			}
		}
	} else {
		local_visited = calloc(howmany(ctx->cluster_count, 8), 1);
		while (exfat_cluster_is_valid(curr_cn, ctx->cluster_count)) {
			uint8_t *new_buf;
			uint32_t idx, next_cn;

			idx = EXFAT_CNTOI(curr_cn);
			if (local_visited != NULL) {
				if ((local_visited[idx / 8] &
				    (1U << (idx % 8))) != 0) {
					if (chain_bad != NULL)
						*chain_bad = true;
					break;
				}
				local_visited[idx / 8] |=
				    (uint8_t)(1U << (idx % 8));
			}
			if (visited_bitmap != NULL)
				visited_bitmap[idx / 8] |=
				    (uint8_t)(1U << (idx % 8));

			new_buf = realloc(buf, (num_clusters + 1) *
			    ctx->cluster_size);
			if (new_buf == NULL) {
				free(local_visited);
				free(buf);
				return (ENOMEM);
			}
			buf = new_buf;

			error = read_cluster(ctx, curr_cn,
			    buf + (num_clusters * ctx->cluster_size));
			if (error != 0) {
				free(local_visited);
				free(buf);
				return (error);
			}
			num_clusters++;

			error = fat_get(ctx, curr_cn, &next_cn);
			if (error != 0) {
				free(local_visited);
				free(buf);
				return (error);
			}

			if (EXFAT_FAT_IS_EOF(next_cn))
				break;
			if (!exfat_cluster_is_valid(next_cn,
			    ctx->cluster_count) ||
			    num_clusters >= max_clusters) {
				if (chain_bad != NULL)
					*chain_bad = true;
				break;
			}
			curr_cn = next_cn;
		}
		free(local_visited);
	}

	if (buf == NULL || num_clusters == 0)
		return (EIO);

	*out_buf = buf;
	*out_slots = (num_clusters * ctx->cluster_size) /
	    sizeof(union exfat_dentry);
	return (0);
}

/*
 * Return true if UTF-16 code unit c is forbidden in exFAT names and volume
 * labels (Spec §7.3.3, §7.7.3).
 */
static bool
is_forbidden_exfat_char(uint16_t c)
{
	if (c < 0x0020)
		return (true);
	switch (c) {
	case '"':
	case '*':
	case '/':
	case ':':
	case '<':
	case '>':
	case '?':
	case '\\':
	case '|':
		return (true);
	default:
		return (false);
	}
}

/*
 * Measure the length of a FAT chain starting at first_cn in fat_idx and
 * report whether it terminates cleanly with EXFAT_FAT_EOF.
 */
static void
measure_fat_chain(struct faultgen_ctx *ctx, uint8_t fat_idx,
    uint32_t first_cn, uint32_t *len_out, bool *eof_out)
{
	uint32_t cur, len, next;
	bool eof;

	len = 0;
	cur = first_cn;
	eof = false;
	while (exfat_cluster_is_valid(cur, ctx->cluster_count) &&
	    len <= ctx->cluster_count) {
		if (fat_get_entry(ctx, fat_idx, cur, &next) != 0 ||
		    EXFAT_FAT_IS_BAD(next))
			break;
		len++;
		if (EXFAT_FAT_IS_EOF(next)) {
			eof = true;
			break;
		}
		cur = next;
	}
	*len_out = len;
	*eof_out = eof;
}

/*
 * Validate file name characters per Spec §7.7.3.
 */
static bool
is_valid_file_name(const uint16_t *name, size_t nchars)
{
	bool has_non_space;

	if (nchars == 0)
		return (false);

	has_non_space = false;
	for (size_t i = 0; i < nchars; i++) {
		if (is_forbidden_exfat_char(name[i]))
			return (false);
		if (name[i] != 0x0020)
			has_non_space = true;
	}
	return (has_non_space);
}

/*
 * Validate volume label characters per Spec §7.3.3.
 */
bool
is_valid_volume_label(const uint16_t *label, size_t nchars)
{
	if (nchars == 0)
		return (true);
	if (nchars > EXFAT_MAX_VOLUME_LABEL_CHARS)
		return (false);

	for (size_t i = 0; i < nchars; i++)
		if (is_forbidden_exfat_char(label[i]))
			return (false);
	return (true);
}

/*
 * Extract UTF-16 filename from exFAT File Name secondary entries (Spec §7.7).
 * Returns the number of UTF-16 characters extracted.
 */
size_t
extract_dentry_utf16(const union exfat_dentry *dent_set, uint8_t sec_count,
    uint16_t *utf16_buf, size_t max_chars)
{
	size_t name_chars;
	uint8_t name_len;

	if (dent_set == NULL || utf16_buf == NULL || max_chars == 0)
		return (0);

	utf16_buf[0] = 0;
	if (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
	    dent_set[1].type != EXFAT_ENTRY_STREAM)
		return (0);

	name_len = dent_set[1].stream.se_name_length;
	name_chars = 0;
	for (size_t s = 2; s <= sec_count && name_chars < name_len; s++) {
		if (dent_set[s].type != EXFAT_ENTRY_NAME)
			break;
		for (size_t c = 0; c < EXFAT_CHARS_PER_NAME_ENTRY &&
		    name_chars < name_len && name_chars + 1 < max_chars; c++)
			utf16_buf[name_chars++] =
			    le16toh(dent_set[s].name.ne_file_name[c]);
	}
	utf16_buf[name_chars] = 0;
	return (name_chars);
}

/*
 * Compute 16-bit NameHash over a UTF-16 filename using the Up-case Table
 * (or ASCII fallback when upcase_table is NULL) per Spec §7.6.4.
 */
uint16_t
calc_utf16_name_hash(const uint16_t *name, size_t nchars,
    const uint16_t *upcase_table)
{
	uint16_t hash;

	hash = 0;
	for (size_t i = 0; i < nchars; i++) {
		uint16_t uc = name[i];

		if (upcase_table != NULL)
			uc = upcase_table[uc];
		else if (uc >= 'a' && uc <= 'z')
			uc -= ('a' - 'A');
		hash = exfat_calc_name_hash(uc, hash);
	}
	return (hash);
}

/*
 * Extract UTF-8 filename from exFAT File Name secondary entries (Spec §7.7).
 */
void
extract_dentry_name(const union exfat_dentry *dent_set, uint8_t sec_count,
    char *name_buf, size_t buf_size)
{
	uint16_t utf16_name[EXFAT_MAX_NAME_CHARS + 1];
	size_t name_chars;

	if (name_buf == NULL || buf_size == 0)
		return;

	name_buf[0] = '\0';
	name_chars = extract_dentry_utf16(dent_set, sec_count, utf16_name,
	    nitems(utf16_name));
	utf16_to_utf8(utf16_name, name_chars, name_buf, buf_size);
}

/*
 * Dump a directory entry set (File and secondary entries) (Spec §6.3, §7.4).
 */
static size_t
dump_file_entry_set(struct faultgen_ctx *ctx,
    const union exfat_dentry *dentries, size_t s, size_t total_slots,
    const char *dir_path, const char *target, bool match_dir,
    struct dentry_stats *stats, struct dir_queue *queue,
    uint8_t *visited_bitmap, const uint16_t *upcase_table, bool *target_found,
    bool verbose)
{
	const struct exfat_dentry_file *fe = &dentries[s].file;
	const struct exfat_dentry_stream *stream = NULL;
	uint16_t actual_cs, attr, calc_cs;
	uint8_t sec_count = fe->fe_secondary_count;
	bool cs_valid, fe_res_bad, has_stream = false, is_dir;
	bool match_file, print_all, sec_types_bad = false;
	char attr_str[128];
	char ts_acc[64], ts_create[64], ts_mod[64];
	char name_utf8[EXFAT_MAX_NAME_CHARS * 3 + 1];
	uint16_t utf16_name[EXFAT_MAX_NAME_CHARS + 1];
	size_t name_chars = 0;

	attr = le16toh(fe->fe_file_attributes);
	is_dir = (attr & EXFAT_ATTR_DIRECTORY) != 0;
	stats->entry_set_count++;
	if (is_dir)
		stats->subdir_count++;
	else
		stats->file_count++;

	if (s + 1 + sec_count > total_slots) {
		size_t avail = total_slots - s - 1;
		size_t consume = 1;

		while (consume <= avail &&
		    (dentries[s + consume].type &
		    (EXFAT_ENTRY_TYPE_IN_USE | EXFAT_ENTRY_TYPE_SECONDARY)) ==
		    (EXFAT_ENTRY_TYPE_IN_USE | EXFAT_ENTRY_TYPE_SECONDARY))
			consume++;
		if (verbose && (match_dir || target == NULL))
			printf("  [Slot %4zu] 0x85 File Directory Entry "
			    "[TRUNCATED ENTRY SET]\n", s);
		stats->anomalies_count++;
		return (consume);
	}

	calc_cs = exfat_dentry_calc_checksum(&dentries[s], 1 + sec_count);
	actual_cs = le16toh(fe->fe_set_checksum);
	cs_valid = (calc_cs == actual_cs);
	if (!cs_valid)
		stats->csum_mismatch_count++;
	if (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
	    sec_count > EXFAT_MAX_SECONDARY_COUNT)
		stats->anomalies_count++;
	fe_res_bad = (fe->fe_reserved1 != 0 || (attr & ~0x0037) != 0 ||
	    fe->fe_create_10ms_increment > 199 ||
	    fe->fe_last_modified_10ms_increment > 199 ||
	    !is_valid_utc_offset(fe->fe_create_tz_offset) ||
	    !is_valid_utc_offset(fe->fe_last_modified_tz_offset) ||
	    !is_valid_utc_offset(fe->fe_last_access_tz_offset) ||
	    !is_valid_timestamp(le32toh(fe->fe_create_timestamp)) ||
	    !is_valid_timestamp(le32toh(fe->fe_last_modified_timestamp)) ||
	    !is_valid_timestamp(le32toh(fe->fe_last_access_timestamp)) ||
	    !is_all_zero(fe->fe_reserved2, sizeof(fe->fe_reserved2)));
	if (fe_res_bad)
		stats->anomalies_count++;

	format_attributes(attr, attr_str, sizeof(attr_str));
	format_dos_timestamp(le32toh(fe->fe_create_timestamp),
	    fe->fe_create_10ms_increment, fe->fe_create_tz_offset,
	    ts_create, sizeof(ts_create));
	format_dos_timestamp(le32toh(fe->fe_last_modified_timestamp),
	    fe->fe_last_modified_10ms_increment, fe->fe_last_modified_tz_offset,
	    ts_mod, sizeof(ts_mod));
	format_dos_timestamp(le32toh(fe->fe_last_access_timestamp),
	    0, fe->fe_last_access_tz_offset, ts_acc, sizeof(ts_acc));

	if (sec_count >= 1 && dentries[s + 1].type == EXFAT_ENTRY_STREAM) {
		has_stream = true;
		stream = &dentries[s + 1].stream;
	}

	name_chars = extract_dentry_utf16(&dentries[s], sec_count, utf16_name,
	    nitems(utf16_name));
	utf16_to_utf8(utf16_name, name_chars, name_utf8, sizeof(name_utf8));
	if (name_utf8[0] == '\0')
		snprintf(name_utf8, sizeof(name_utf8), "%s",
		    is_dir ? "<directory>" : "<file>");

	match_file = false;
	if (target != NULL && !match_dir) {
		char full_path[1024];

		if (strcmp(dir_path, "/") == 0)
			snprintf(full_path, sizeof(full_path), "/%s",
			    name_utf8);
		else
			snprintf(full_path, sizeof(full_path), "%s/%s",
			    dir_path, name_utf8);
		if (strcasecmp(name_utf8, target) == 0 ||
		    strcasecmp(full_path, target) == 0 ||
		    (full_path[0] == '/' &&
		    strcasecmp(full_path + 1, target) == 0)) {
			match_file = true;
			if (target_found != NULL)
				*target_found = true;
		}
	}

	if (!has_stream)
		stats->anomalies_count++;
	else {
		uint8_t num_name_entries;

		num_name_entries = howmany(stream->se_name_length,
		    EXFAT_CHARS_PER_NAME_ENTRY);
		sec_types_bad = (sec_count < 1 + num_name_entries);
		for (size_t j = 2; j <= sec_count; j++) {
			uint8_t stype = dentries[s + j].type;

			if (j <= (size_t)1 + num_name_entries) {
				if (stype != EXFAT_ENTRY_NAME ||
				    dentries[s + j].name.ne_general_flags != 0)
					sec_types_bad = true;
			} else if ((stype & (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) !=
			    (EXFAT_ENTRY_TYPE_IN_USE |
			    EXFAT_ENTRY_TYPE_SECONDARY |
			    EXFAT_ENTRY_TYPE_BENIGN)) {
				sec_types_bad = true;
			} else if (stype == EXFAT_ENTRY_VENDOR_EXT &&
			    dentries[s + j].vendor_ext.ve_general_flags != 0) {
				sec_types_bad = true;
			} else if (stype == EXFAT_ENTRY_VENDOR_ALLOC) {
				uint8_t vf = dentries[s + j].vendor_alloc.
				    va_general_flags;
				uint32_t va_cn = le32toh(dentries[s + j].
				    vendor_alloc.va_first_cluster);
				uint64_t va_len = le64toh(dentries[s + j].
				    vendor_alloc.va_data_length);

				if ((vf & ~(EXFAT_FLAG_ALLOC_POSSIBLE |
				    EXFAT_FLAG_NO_FAT_CHAIN)) != 0 ||
				    (vf & EXFAT_FLAG_ALLOC_POSSIBLE) == 0 ||
				    (va_len == 0 && va_cn != 0) ||
				    (va_len > 0 && !exfat_cluster_is_valid(
				    va_cn, ctx->cluster_count)))
					sec_types_bad = true;
			}
		}
		if (stream->se_name_length == 0 ||
		    name_chars != stream->se_name_length || sec_types_bad)
			stats->anomalies_count++;
		if (!is_valid_file_name(utf16_name, name_chars))
			stats->anomalies_count++;
	}

	print_all = verbose && (target == NULL || match_dir || match_file);

	if (print_all) {
		printf("  [Slot %4zu] 0x85 File Directory Entry: \"%s\" "
		    "(Spec §7.4)\n", s, name_utf8);
		printf("               Attributes:      %s\n", attr_str);
		printf("               SecondaryCount:  %u%s\n", sec_count,
		    (sec_count < EXFAT_MIN_SECONDARY_COUNT ||
		    sec_count > EXFAT_MAX_SECONDARY_COUNT) ?
		    " [DEFECT: Out of range (2..18), Spec §7.4.2]" : "");
		printf("               SetChecksum:     0x%04" PRIX16 " %s",
		    actual_cs, cs_valid ? "[VALID]" : "[MISMATCH!]");
		if (!cs_valid)
			printf(" (Calculated: 0x%04" PRIX16 ")", calc_cs);
		printf("\n");
		if (fe_res_bad)
			printf("               [DEFECT: Invalid File reserved "
			    "fields, attributes, timestamps, or UTC offsets, "
			    "Spec §7.4]\n");
		if (!has_stream) {
			printf("               [DEFECT: Missing Stream "
			    "Extension directory entry, Spec §7.4]\n");
		} else {
			if (stream->se_name_length == 0)
				printf("               [DEFECT: NameLength is "
				    "0, Spec §7.6.3]\n");
			else if (name_chars != stream->se_name_length)
				printf("               [DEFECT: NameLength "
				    "(%u) does not match extracted "
				    "characters (%zu), Spec §7.6.3]\n",
				    stream->se_name_length, name_chars);
			else if (sec_types_bad)
				printf("               [DEFECT: Secondary "
				    "entry count or types invalid, "
				    "Spec §7.4.2]\n");
			if (!is_valid_file_name(utf16_name, name_chars))
				printf("               [DEFECT: File Name "
				    "contains invalid character(s), "
				    "Spec §7.7.3]\n");
		}
		printf("               Timestamps:\n");
		printf("                 Created:       %s\n", ts_create);
		printf("                 Modified:      %s\n", ts_mod);
		printf("                 Accessed:      %s\n", ts_acc);
	}

	if (has_stream) {
		char flags_str[128];
		uint64_t dl, vdl;
		uint32_t stream_cn;
		uint16_t calc_hash, name_hash;
		uint8_t flags;
		bool cn_valid, dir_dl_valid, flags_bad, hash_valid;
		bool se_res_bad, vdl_valid;

		flags = stream->se_general_flags;
		stream_cn = le32toh(stream->se_first_cluster);
		dl = le64toh(stream->se_data_length);
		vdl = le64toh(stream->se_valid_data_length);
		name_hash = le16toh(stream->se_name_hash);
		calc_hash = calc_utf16_name_hash(utf16_name, name_chars,
		    upcase_table);
		hash_valid = (calc_hash == name_hash);
		vdl_valid = is_dir ? (vdl == dl) : (vdl <= dl);
		cn_valid = (!is_dir && dl == 0) ? (stream_cn == 0) :
		    exfat_cluster_is_valid(stream_cn, ctx->cluster_count);
		dir_dl_valid = !is_dir || (dl >= ctx->cluster_size &&
		    dl <= EXFAT_MAX_DIR_SIZE && (dl % ctx->cluster_size) == 0);
		flags_bad = ((flags & EXFAT_FLAG_ALLOC_POSSIBLE) == 0 ||
		    (flags & ~(EXFAT_FLAG_ALLOC_POSSIBLE |
		    EXFAT_FLAG_NO_FAT_CHAIN)) != 0 ||
		    ((flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0 &&
		    (stream_cn == 0 || dl == 0)));
		se_res_bad = (stream->se_reserved1 != 0 ||
		    stream->se_reserved2 != 0 || stream->se_reserved3 != 0);

		if (!hash_valid) {
			stats->hash_mismatch_count++;
			stats->anomalies_count++;
		}
		if (!vdl_valid)
			stats->anomalies_count++;
		if (!cn_valid)
			stats->anomalies_count++;
		if (!dir_dl_valid)
			stats->anomalies_count++;
		if (flags_bad || se_res_bad)
			stats->anomalies_count++;

		format_stream_flags(flags, flags_str, sizeof(flags_str));

		if (print_all) {
			printf("    [Slot %4zu] 0xC0 Stream Extension "
			    "(Spec §7.6)\n", s + 1);
			printf("                 Flags:           %s%s\n",
			    flags_str, flags_bad ?
			    " [DEFECT: Invalid GeneralSecondaryFlags, "
			    "Spec §7.6.2]" : "");
			if (se_res_bad)
				printf("                 [DEFECT: Stream "
				    "Extension reserved fields non-zero, "
				    "Spec §7.6]\n");
			printf("                 FirstCluster:    %" PRIu32
			    " %s\n", stream_cn, cn_valid ?
			    "[VALID]" : ((!is_dir && dl == 0) ?
			    "[INVALID: Must be 0 when DataLength is 0, "
			    "Spec §7.6.6]" : "[OUT OF BOUNDS!]"));
			printf("                 DataLength:      %" PRIu64
			    " bytes%s\n", dl, dir_dl_valid ? "" :
			    " [INVALID: Directory size must be multiple of "
			    "cluster size and <= 256MB, Spec §7.6.7]");
			printf("                 ValidDataLength: %" PRIu64
			    " bytes %s\n", vdl, vdl_valid ?
			    "[VALID]" : (is_dir ?
			    "[INVALID: VDL != DataLength, Spec §7.6.5]" :
			    "[INVALID: VDL > DataLength, Spec §7.6.5]"));
			printf("                 NameLength:      %u "
			    "characters\n", stream->se_name_length);
			printf("                 NameHash:        0x%04"
			    PRIX16 " %s\n", name_hash, hash_valid ?
			    "[VALID]" : "[MISMATCH!]");
		}

		/* Subdirectory recursion / loop detection */
		if (is_dir && exfat_cluster_is_valid(stream_cn,
		    ctx->cluster_count)) {
			uint32_t idx = EXFAT_CNTOI(stream_cn);
			bool already_visited = (visited_bitmap != NULL &&
			    (visited_bitmap[idx / 8] & (1U << (idx % 8))) != 0);

			if (already_visited ||
			    stream_cn == ctx->root_dir_cluster) {
				if (print_all)
					printf("                 [INVALID "
					    "DIRECTORY LOOP: Points to "
					    "visited cluster %" PRIu32 "!]\n",
					    stream_cn);
				stats->anomalies_count++;
			} else if (queue != NULL) {
				char subpath[1024];

				if (visited_bitmap != NULL)
					visited_bitmap[idx / 8] |=
					    (uint8_t)(1U << (idx % 8));
				if (strcmp(dir_path, "/") == 0)
					snprintf(subpath, sizeof(subpath),
					    "/%s", name_utf8);
				else
					snprintf(subpath, sizeof(subpath),
					    "%s/%s", dir_path, name_utf8);
				queue_enqueue(queue, stream_cn,
				    (flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0,
				    dl, subpath);
			}
		}

		/* Check NoFatChain continuity and cluster FAT entries */
		if ((flags & EXFAT_FLAG_NO_FAT_CHAIN) != 0 && cn_valid &&
		    stream_cn != 0 && dl > 0) {
			uint64_t needed_clusters;

			needed_clusters = (dl / ctx->cluster_size) +
			    ((dl % ctx->cluster_size) != 0);
			if (needed_clusters > ctx->cluster_count ||
			    (uint64_t)EXFAT_CNTOI(stream_cn) +
			    needed_clusters > ctx->cluster_count) {
				if (print_all)
					printf("                 [DEFECT: "
					    "Contiguous stream extends beyond "
					    "cluster heap (Spec §7.6.7)]\n");
				stats->anomalies_count++;
			} else {
				for (uint64_t ci = 0; ci < needed_clusters;
				    ci++) {
					uint32_t cn = stream_cn + (uint32_t)ci;
					uint32_t fat_val;

					if (fat_get(ctx, cn, &fat_val) != 0)
						break;
					if (EXFAT_FAT_IS_BAD(fat_val)) {
						if (print_all)
							printf("             "
							    "    [DEFECT: "
							    "Cluster %" PRIu32
							    " is marked BAD "
							    "in FAT]\n", cn);
						stats->anomalies_count++;
						break;
					}
					if (ci == 0 &&
					    dl > ctx->cluster_size &&
					    fat_val != EXFAT_FAT_FREE &&
					    fat_val != stream_cn + 1 &&
					    !EXFAT_FAT_IS_EOF(fat_val)) {
						if (print_all)
							printf("             "
							    "    [WARNING: "
							    "NoFatChain set "
							    "but FAT links to "
							    "Cluster %" PRIu32
							    " (fragmented)!]\n",
							    fat_val);
						stats->anomalies_count++;
					}
				}
			}
		}

		/* Verify FAT-chained cluster allocation vs DataLength */
		if ((flags & EXFAT_FLAG_NO_FAT_CHAIN) == 0 && cn_valid &&
		    stream_cn != 0 && dl > 0) {
			uint64_t needed_clusters;
			uint32_t chain_len;
			bool eof_seen;

			needed_clusters = (dl / ctx->cluster_size) +
			    ((dl % ctx->cluster_size) != 0);
			measure_fat_chain(ctx, exfat_active_fat(ctx),
			    stream_cn, &chain_len, &eof_seen);

			if (chain_len < needed_clusters) {
				if (print_all)
					printf("                 "
					    "[DEFECT: DataLength %"
					    PRIu64 " requires %" PRIu64
					    " clusters, FAT chain has "
					    "%" PRIu32
					    " (Spec §7.6.7)]\n",
					    dl, needed_clusters,
					    chain_len);
				stats->anomalies_count++;
			} else if (chain_len > needed_clusters) {
				if (print_all)
					printf("                 "
					    "[DEFECT: FAT chain has %"
					    PRIu32 " clusters, "
					    "DataLength %" PRIu64
					    " requires %" PRIu64
					    " (Spec §7.6.7)]\n",
					    chain_len, dl,
					    needed_clusters);
				stats->anomalies_count++;
			} else if (!eof_seen) {
				if (print_all)
					printf("                 "
					    "[DEFECT: FAT chain does "
					    "not terminate with EOF "
					    "(Spec §4.1.3)]\n");
				stats->anomalies_count++;
			}
		}
	}

	if (ctx->verbose && print_all) {
		for (size_t j = 2; j <= sec_count; j++) {
			uint8_t stype = dentries[s + j].type;

			if (stype == EXFAT_ENTRY_NAME)
				printf("    [Slot %4zu] 0xC1 File Name "
				    "Entry #%zu (Spec §7.7)\n", s + j, j - 1);
			else if (stype == EXFAT_ENTRY_VENDOR_EXT)
				printf("    [Slot %4zu] 0xE0 Vendor "
				    "Extension (Spec §7.8)\n", s + j);
			else if (stype == EXFAT_ENTRY_VENDOR_ALLOC)
				printf("    [Slot %4zu] 0xE1 Vendor "
				    "Allocation (Spec §7.9)\n", s + j);
		}
	}

	return (1 + sec_count);
}

/*
 * Read raw Up-case Table bytes along its FAT cluster chain (Spec §7.2).
 */
static int
read_upcase_data(struct faultgen_ctx *ctx, uint32_t first_cn, size_t data_len,
    uint8_t **buf_out, uint32_t *last_cn_out)
{
	uint8_t *clbuf, *uc_buf;
	uint32_t cur_cn, visited;
	size_t off, rem, to_copy;
	int error;

	uc_buf = malloc(data_len);
	if (uc_buf == NULL)
		return (ENOMEM);

	clbuf = malloc(ctx->cluster_size);
	if (clbuf == NULL) {
		free(uc_buf);
		return (ENOMEM);
	}

	rem = data_len;
	off = 0;
	cur_cn = first_cn;
	visited = 0;
	error = 0;

	while (rem > 0 && exfat_cluster_is_valid(cur_cn, ctx->cluster_count)) {
		error = read_cluster(ctx, cur_cn, clbuf);
		if (error != 0)
			break;
		to_copy = (rem < ctx->cluster_size) ? rem : ctx->cluster_size;
		memcpy(uc_buf + off, clbuf, to_copy);
		rem -= to_copy;
		off += to_copy;
		if (rem > 0) {
			uint32_t next_cn;

			if (fat_get(ctx, cur_cn, &next_cn) != 0 ||
			    ++visited > ctx->cluster_count)
				break;
			cur_cn = next_cn;
		}
	}
	free(clbuf);

	if (error != 0 || rem != 0) {
		free(uc_buf);
		return (error != 0 ? error : EIO);
	}

	*buf_out = uc_buf;
	if (last_cn_out != NULL)
		*last_cn_out = cur_cn;
	return (0);
}

/*
 * Verify Up-case Table directory entry fields and table data checksum
 * (Spec §7.2).
 */
static void
verify_upcase_entry(struct faultgen_ctx *ctx,
    const struct exfat_dentry_upcase *uc, struct dentry_stats *stats,
    uint32_t first_cn, bool print_all, size_t s)
{
	uint8_t *uc_buf;
	uint64_t uc_len;
	uint32_t calc_csum, last_cn, uc_cn, uc_csum;
	int rerr;
	bool chain_bad, csum_checked, csum_match, decomp_bad, dup_upcase;
	bool len_valid, not_root, res_bad;

	uc_cn = le32toh(uc->uc_first_cluster);
	uc_len = le64toh(uc->uc_data_length);
	uc_csum = le32toh(uc->uc_table_checksum);
	csum_checked = false;
	csum_match = true;
	chain_bad = false;
	decomp_bad = false;

	stats->upcase_count++;
	not_root = (first_cn != ctx->root_dir_cluster);
	dup_upcase = (stats->upcase_count > 1);
	res_bad = (!is_all_zero(uc->uc_reserved1, sizeof(uc->uc_reserved1)) ||
	    !is_all_zero(uc->uc_reserved2, sizeof(uc->uc_reserved2)));
	len_valid = (uc_len > 0 && uc_len <= EXFAT_MAX_UPCASE_SIZE &&
	    (uc_len & 1) == 0);
	if (!len_valid || not_root || dup_upcase || res_bad)
		stats->anomalies_count++;

	if (exfat_cluster_is_valid(uc_cn, ctx->cluster_count) &&
	    uc_len <= EXFAT_MAX_UPCASE_SIZE && uc_len > 0) {
		rerr = read_upcase_data(ctx, uc_cn, (size_t)uc_len, &uc_buf,
		    &last_cn);
		if (rerr == 0) {
			uint32_t end_next_cn;
			uint16_t *table;

			if (fat_get(ctx, last_cn, &end_next_cn) != 0 ||
			    !EXFAT_FAT_IS_EOF(end_next_cn)) {
				chain_bad = true;
				stats->anomalies_count++;
			}
			calc_csum = exfat_boot_checksum(uc_buf,
			    (size_t)uc_len, 0);
			csum_checked = true;
			csum_match = (calc_csum == uc_csum);
			if (!csum_match)
				stats->csum_mismatch_count++;
			table = malloc(EXFAT_UPCASE_TABLE_CHARS *
			    sizeof(*table));
			if (table != NULL) {
				if ((uc_len & 1) == 0 &&
				    decompress_upcase(uc_buf, (size_t)uc_len,
				    table) != 0) {
					decomp_bad = true;
					stats->anomalies_count++;
				}
				free(table);
			}
			free(uc_buf);
		} else if (rerr != ENOMEM) {
			chain_bad = true;
			stats->anomalies_count++;
		}
	} else if (!exfat_cluster_is_valid(uc_cn, ctx->cluster_count))
		stats->anomalies_count++;

	if (!print_all)
		return;

	printf("  [Slot %4zu] 0x82 Up-case Table Directory Entry "
	    "(Spec §7.2)\n", s);
	printf("               FirstCluster:    %" PRIu32 " %s\n", uc_cn,
	    exfat_cluster_is_valid(uc_cn, ctx->cluster_count) ?
	    "[VALID]" : "[OUT OF BOUNDS]");
	printf("               DataLength:      %" PRIu64 " bytes %s\n", uc_len,
	    len_valid ? "[VALID]" :
	    "[ANOMALY: Spec §7.2.4 requires non-zero even size <= 131,072 "
	    "bytes]");
	if (csum_checked)
		printf("               TableChecksum:   0x%08" PRIX32 " %s\n",
		    uc_csum, csum_match ? "[VALID]" : "[MISMATCH]");
	else
		printf("               TableChecksum:   0x%08" PRIX32 "\n",
		    uc_csum);
	if (chain_bad)
		printf("               [DEFECT: Up-case Table FAT chain "
		    "truncated or not EOF-terminated, Spec §7.2]\n");
	if (decomp_bad)
		printf("               [DEFECT: Up-case Table decompression "
		    "failed, Spec §7.2]\n");
	if (dup_upcase)
		printf("               [DEFECT: Duplicate Up-case Table, "
		    "Spec §7.2.1]\n");
	if (not_root)
		printf("               [DEFECT: Up-case Table outside root "
		    "directory, Spec §7.2.1]\n");
	if (res_bad)
		printf("               [DEFECT: Reserved fields non-zero, "
		    "Spec §7.2]\n");
}

/*
 * Verify Allocation Bitmap directory entry fields and FAT chain (Spec §7.1).
 */
static void
verify_bitmap_entry(struct faultgen_ctx *ctx,
    const struct exfat_dentry_bitmap *bm, struct dentry_stats *stats,
    uint32_t first_cn, bool *seen_bm0, bool *seen_bm1, bool print_all,
    size_t s)
{
	uint32_t bm_cn = le32toh(bm->bm_first_cluster);
	uint64_t bm_len = le64toh(bm->bm_data_length);
	uint64_t req_len = howmany((uint64_t)ctx->cluster_count, 8);
	bool cn_bad = !exfat_cluster_is_valid(bm_cn, ctx->cluster_count);
	bool truncated = (bm_len < req_len);
	bool exceeds_max = (bm_len > EXFAT_MAX_BITMAP_SIZE);
	bool is_second = (bm->bm_flags & EXFAT_BITMAP_FLAG_SECOND) != 0;
	bool flags_bad = (bm->bm_flags & 0xFE) != 0;
	bool res_bad = !is_all_zero(bm->bm_reserved, sizeof(bm->bm_reserved));
	bool sec_on_single = (ctx->num_fats == 1 && is_second);
	bool dup_bm = is_second ? *seen_bm1 : *seen_bm0;
	bool not_root = (first_cn != ctx->root_dir_cluster);
	bool chain_bad = false;

	if (is_second)
		*seen_bm1 = true;
	else
		*seen_bm0 = true;

	if (!cn_bad && !exceeds_max && bm_len > 0) {
		uint64_t needed_bm;
		uint32_t bm_len_cnt;
		uint8_t bm_fat;
		bool bm_eof;

		needed_bm = howmany(bm_len, (uint64_t)ctx->cluster_size);
		bm_fat = (is_second && ctx->num_fats > 1) ? 1 : 0;
		measure_fat_chain(ctx, bm_fat, bm_cn, &bm_len_cnt, &bm_eof);
		if (bm_len_cnt != needed_bm || !bm_eof)
			chain_bad = true;
	}

	stats->bitmap_count++;
	if (cn_bad || truncated || exceeds_max || flags_bad || res_bad ||
	    sec_on_single || dup_bm || not_root || chain_bad)
		stats->anomalies_count++;

	if (!print_all)
		return;

	printf("  [Slot %4zu] 0x81 Allocation Bitmap Directory Entry "
	    "(Spec §7.1)\n", s);
	printf("               Bitmap:          #%u (%s Bitmap)%s\n",
	    is_second ? 1 : 0, is_second ? "Second" : "First",
	    sec_on_single ? " [DEFECT: Second on single-FAT volume]" : "");
	if (flags_bad)
		printf("               BitmapFlags:     0x%02X [DEFECT: "
		    "Reserved bits, Spec §7.1.2]\n", bm->bm_flags);
	if (res_bad)
		printf("               [DEFECT: Reserved fields non-zero, "
		    "Spec §7.1]\n");
	printf("               FirstCluster:    %" PRIu32 " %s\n", bm_cn,
	    cn_bad ? "[OUT OF BOUNDS]" : "[VALID]");
	printf("               DataLength:      %" PRIu64 " bytes %s\n", bm_len,
	    truncated ? "[TRUNCATED: Does not cover full cluster heap]" :
	    (exceeds_max ? "[DEFECT: Exceeds maximum bitmap size (512MB), "
	    "Spec §7.1.4]" : "[VALID]"));
	if (chain_bad)
		printf("               [DEFECT: Allocation Bitmap FAT chain "
		    "truncated or not EOF-terminated, Spec §7.1]\n");
	if (dup_bm)
		printf("               [DEFECT: Duplicate Allocation Bitmap "
		    "#%u, Spec §7.1.1]\n", is_second ? 1 : 0);
	if (not_root)
		printf("               [DEFECT: Bitmap outside root directory, "
		    "Spec §7.1.1]\n");
}

/*
 * Verify Volume Label directory entry fields and characters (Spec §7.3).
 */
static void
verify_volume_label_entry(struct faultgen_ctx *ctx,
    const struct exfat_dentry_volume_label *vl, struct dentry_stats *stats,
    uint32_t first_cn, bool print_all, size_t s)
{
	uint16_t label_chars[EXFAT_MAX_VOLUME_LABEL_CHARS];
	char label_utf8[EXFAT_MAX_VOLUME_LABEL_CHARS * 3 + 1];
	bool dup_label, invalid_chars, len_bad, not_root, res_bad;

	stats->label_count++;
	not_root = (first_cn != ctx->root_dir_cluster);
	dup_label = (stats->label_count > 1);
	len_bad = (vl->vl_character_count > EXFAT_MAX_VOLUME_LABEL_CHARS);
	res_bad = !is_all_zero(vl->vl_reserved, sizeof(vl->vl_reserved));
	for (size_t k = 0; k < EXFAT_MAX_VOLUME_LABEL_CHARS; k++)
		label_chars[k] = le16toh(vl->vl_volume_label[k]);
	invalid_chars = !is_valid_volume_label(label_chars,
	    vl->vl_character_count);
	if (not_root || dup_label || len_bad || invalid_chars || res_bad)
		stats->anomalies_count++;

	if (!print_all)
		return;

	utf16_to_utf8(label_chars,
	    len_bad ? EXFAT_MAX_VOLUME_LABEL_CHARS : vl->vl_character_count,
	    label_utf8, sizeof(label_utf8));
	printf("  [Slot %4zu] 0x83 Volume Label Directory Entry (Spec §7.3)\n",
	    s);
	printf("               CharacterCount:  %u%s\n", vl->vl_character_count,
	    len_bad ? " [DEFECT: Exceeds 11 characters, Spec §7.3.2]" : "");
	printf("               VolumeLabel:     \"%s\"%s\n", label_utf8,
	    invalid_chars ? " [DEFECT: Invalid character(s), Spec §7.3.3]" :
	    "");
	if (res_bad)
		printf("               [DEFECT: Reserved fields non-zero, "
		    "Spec §7.3]\n");
	if (dup_label)
		printf("               [DEFECT: Duplicate Volume Label, "
		    "Spec §7.3.1]\n");
	if (not_root)
		printf("               [DEFECT: Volume Label outside root "
		    "directory, Spec §7.3.1]\n");
}

/*
 * Verify Volume GUID directory entry fields and SetChecksum (Spec §7.5).
 */
static void
verify_volume_guid_entry(struct faultgen_ctx *ctx,
    const union exfat_dentry *dent, struct dentry_stats *stats,
    uint32_t first_cn, bool print_all, size_t s)
{
	const struct exfat_dentry_volume_guid *vg = &dent->volume_guid;
	char guid_str[48];
	uint16_t actual_cs, calc_cs;
	bool csum_bad, dup_guid, flags_bad, not_root;
	bool null_guid, res_bad, sec_bad;

	stats->guid_count++;
	not_root = (first_cn != ctx->root_dir_cluster);
	dup_guid = (stats->guid_count > 1);
	sec_bad = (vg->vg_secondary_count != 0);
	flags_bad = (le16toh(vg->vg_general_flags) != 0);
	null_guid = is_all_zero(vg->vg_guid, sizeof(vg->vg_guid));
	res_bad = !is_all_zero(vg->vg_reserved, sizeof(vg->vg_reserved));
	calc_cs = exfat_dentry_calc_checksum(dent, 1);
	actual_cs = le16toh(vg->vg_set_checksum);
	csum_bad = (calc_cs != actual_cs);

	if (csum_bad)
		stats->csum_mismatch_count++;
	if (not_root || dup_guid || sec_bad || flags_bad || null_guid ||
	    res_bad)
		stats->anomalies_count++;

	if (!print_all)
		return;

	format_guid(vg->vg_guid, guid_str, sizeof(guid_str));
	printf("  [Slot %4zu] 0xA0 Volume GUID Directory Entry (Spec §7.5)\n",
	    s);
	printf("               GUID:            %s%s\n", guid_str,
	    null_guid ? " [DEFECT: Null GUID, Spec §7.5.5]" : "");
	if (sec_bad)
		printf("               SecondaryCount:  %u [DEFECT: Must be 0, "
		    "Spec §7.5.2]\n", vg->vg_secondary_count);
	if (flags_bad)
		printf("               GeneralFlags:    0x%04" PRIX16
		    " [DEFECT: Must be 0, Spec §7.5.4]\n",
		    le16toh(vg->vg_general_flags));
	if (res_bad)
		printf("               [DEFECT: Reserved fields non-zero, "
		    "Spec §7.5]\n");
	printf("               SetChecksum:     0x%04" PRIX16 " %s\n",
	    actual_cs, csum_bad ? "[MISMATCH!]" : "[VALID]");
	if (dup_guid)
		printf("               [DEFECT: Duplicate Volume GUID, "
		    "Spec §7.5.1]\n");
	if (not_root)
		printf("               [DEFECT: Volume GUID outside root "
		    "directory, Spec §7.5.1]\n");
}

/*
 * Dump directory entries in a single directory cluster chain (Spec §6.3).
 */
static int
dump_single_directory(struct faultgen_ctx *ctx, uint32_t first_cn,
    const char *dir_path, bool no_fat_chain, uint64_t data_len,
    const char *target, struct dentry_stats *stats, struct dir_queue *queue,
    uint8_t *visited_bitmap, const uint16_t *upcase_table, bool *target_found,
    bool verbose)
{
	uint8_t *buf = NULL;
	union exfat_dentry *dentries;
	size_t total_slots = 0;
	int error;
	bool dir_chain_bad = false, match_dir, print_all;
	bool seen_bm0 = false, seen_bm1 = false;

	if (visited_bitmap != NULL) {
		uint32_t idx = EXFAT_CNTOI(first_cn);

		visited_bitmap[idx / 8] |= (uint8_t)(1U << (idx % 8));
	}
	stats->dir_count++;

	error = load_directory_clusters(ctx, first_cn, no_fat_chain, data_len,
	    visited_bitmap, &dir_chain_bad, &buf, &total_slots);
	if (error != 0) {
		if (verbose)
			printf("Directory %s (Cluster %" PRIu32 "): "
			    "Failed to load clusters (error %d)\n",
			    dir_path, first_cn, error);
		return (error);
	}
	if (dir_chain_bad)
		stats->anomalies_count++;

	match_dir = false;
	if (target != NULL) {
		const char *p = dir_path;

		if (*p == '/' && *(p + 1) != '\0')
			p++;
		if (strcasecmp(dir_path, target) == 0 ||
		    strcasecmp(p, target) == 0) {
			match_dir = true;
			if (target_found != NULL)
				*target_found = true;
		}
	}
	print_all = verbose && (target == NULL || match_dir);

	if (print_all) {
		printf("\nDirectory: %s (Cluster %" PRIu32 ", %zu slots, "
		    "Spec §6.3):\n", dir_path, first_cn, total_slots);
		if (ctx->verbose) {
			uint64_t sec = exfat_cluster_to_sector(
			    ctx->cluster_heap_offset, ctx->cluster_shift,
			    first_cn);
			off_t off = (off_t)sec << ctx->sector_shift;

			printf("  Location:       Sector %" PRIu64
			    ", Offset 0x%" PRIx64 "\n", sec, (uint64_t)off);
		}
	}

	dentries = (union exfat_dentry *)buf;
	for (size_t s = 0; s < total_slots; ) {
		uint8_t type = dentries[s].type;

		if (type == EXFAT_ENTRY_EOD) {
			size_t zero_count = 0;

			if (print_all)
				printf("  [Slot %4zu] 0x00 End-of-Directory "
				    "(EOD)\n", s);
			s++;

			while (s < total_slots &&
			    dentries[s].type == EXFAT_ENTRY_EOD) {
				zero_count++;
				s++;
			}
			if (zero_count > 0 && ctx->verbose && print_all)
				printf("              (%zu empty slots to "
				    "next entry or cluster end)\n", zero_count);
			if (!verbose)
				break;
			continue;
		}

		if ((type & EXFAT_ENTRY_TYPE_IN_USE) == 0) {
			if (print_all)
				printf("  [Slot %4zu] 0x%02X Deleted / "
				    "Unused Entry (TypeCode 0x%02X)\n",
				    s, type,
				    type & EXFAT_ENTRY_TYPE_CODE_MASK);
			stats->deleted_count++;
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_BITMAP) {
			verify_bitmap_entry(ctx, &dentries[s].bitmap, stats,
			    first_cn, &seen_bm0, &seen_bm1, print_all, s);
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_UPCASE) {
			verify_upcase_entry(ctx, &dentries[s].upcase, stats,
			    first_cn, print_all, s);
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_VOLUME_LABEL) {
			verify_volume_label_entry(ctx,
			    &dentries[s].volume_label, stats, first_cn,
			    print_all, s);
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_VOLUME_GUID) {
			verify_volume_guid_entry(ctx, &dentries[s], stats,
			    first_cn, print_all, s);
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_TEXFAT_PADDING) {
			struct exfat_dentry_texfat_padding *tp =
			    &dentries[s].texfat_padding;
			uint16_t actual_cs, calc_cs;
			bool csum_bad, flags_bad, res_bad, sec_bad;

			sec_bad = (tp->tp_secondary_count != 0);
			flags_bad = (le16toh(tp->tp_general_flags) != 0);
			res_bad = !is_all_zero(tp->tp_reserved,
			    sizeof(tp->tp_reserved));
			calc_cs = exfat_dentry_calc_checksum(&dentries[s], 1);
			actual_cs = le16toh(tp->tp_set_checksum);
			csum_bad = (calc_cs != actual_cs);
			if (csum_bad)
				stats->csum_mismatch_count++;
			if (sec_bad || flags_bad || res_bad)
				stats->anomalies_count++;
			if (print_all)
				printf("  [Slot %4zu] 0xA1 TexFAT Padding "
				    "Directory Entry (Spec §7.10)\n", s);
			s++;
			continue;
		}

		if (type == EXFAT_ENTRY_FILE) {
			s += dump_file_entry_set(ctx, dentries, s, total_slots,
			    dir_path, target, match_dir, stats, queue,
			    visited_bitmap, upcase_table, target_found,
			    verbose);
			continue;
		}

		if ((type & EXFAT_ENTRY_TYPE_SECONDARY) != 0) {
			stats->orphaned_secondary_count++;
			stats->anomalies_count++;
			if (print_all) {
				printf("  [Slot %4zu] 0x%02X ORPHANED "
				    "SECONDARY ENTRY (Spec §6.3, §6.4)\n",
				    s, type);
				printf("               [DEFECT: Secondary "
				    "entry without preceding primary "
				    "File Entry]\n");
			}
			s++;
			continue;
		}

		if ((type & EXFAT_ENTRY_TYPE_BENIGN) == 0)
			stats->anomalies_count++;
		if (print_all)
			printf("  [Slot %4zu] 0x%02X Unknown Directory "
			    "Entry\n", s, type);
		s++;
	}

	free(buf);
	return (0);
}

/*
 * Print summary statistics for directory entries (Spec §6.3, §7.4).
 */
static void
print_dentry_summary(const struct dentry_stats *stats)
{
	printf("\nDirectory Entries Summary (Spec §6.3, §7.4):\n");
	printf("  Directories inspected:      %zu\n", stats->dir_count);
	printf("  Directory entry sets:       %zu\n", stats->entry_set_count);
	printf("  Files:                      %zu\n", stats->file_count);
	printf("  Subdirectories:             %zu\n", stats->subdir_count);
	printf("  Allocation Bitmaps:         %zu\n", stats->bitmap_count);
	printf("  Up-case Tables:             %zu\n", stats->upcase_count);
	printf("  Volume Labels:              %zu\n", stats->label_count);
	printf("  Volume GUIDs:               %zu\n", stats->guid_count);
	printf("  Deleted / unused slots:     %zu\n", stats->deleted_count);
	printf("  Checksum mismatches:        %zu\n",
	    stats->csum_mismatch_count);
	printf("  NameHash mismatches:        %zu\n",
	    stats->hash_mismatch_count);
	if (stats->orphaned_secondary_count > 0)
		printf("  Orphaned secondaries:       %zu\n",
		    stats->orphaned_secondary_count);
	if (stats->anomalies_count > 0)
		printf("  Total anomalies / defects:  %zu\n",
		    stats->anomalies_count);

	if (stats->csum_mismatch_count == 0 && stats->anomalies_count == 0)
		printf("\nDirectory Consistency: ALL DENTRIES AND CHECKSUMS "
		    "ARE VALID\n");
	else
		printf("\nDirectory Consistency: DEFECTS DETECTED (%zu "
		    "checksum mismatches, %zu anomalies)\n",
		    stats->csum_mismatch_count, stats->anomalies_count);
}

/*
 * Traverse directory tree starting from Root Directory or specific cluster.
 */
int
dentry_scan_tree(struct faultgen_ctx *ctx, const char *target,
    struct dentry_stats *stats, bool verbose)
{
	struct dir_queue queue;
	struct dir_item item;
	uint8_t *visited_bitmap;
	uint16_t *upcase_table;
	const char *match_target;
	int error;
	bool target_found;

	memset(stats, 0, sizeof(*stats));
	target_found = false;
	match_target = NULL;
	upcase_table = NULL;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	(void)load_upcase_table(ctx, &upcase_table);

	if (target != NULL && *target != '\0' && strcmp(target, "/") != 0 &&
	    strcmp(target, "root") != 0) {
		uint32_t cn_val;

		if (parse_u32_str(target, NULL, &cn_val) == 0) {
			if (!exfat_cluster_is_valid(cn_val,
			    ctx->cluster_count)) {
				free(upcase_table);
				return (EINVAL);
			}
			error = dump_single_directory(ctx, cn_val,
			    "<cluster>", false, 0, NULL, stats, NULL, NULL,
			    upcase_table, NULL, verbose);
			free(upcase_table);
			return (error);
		}
		match_target = target;
	}

	error = queue_init(&queue);
	if (error != 0) {
		free(upcase_table);
		return (error);
	}

	visited_bitmap = calloc(howmany(ctx->cluster_count, 8), 1);
	if (visited_bitmap == NULL) {
		free(upcase_table);
		queue_free(&queue);
		return (ENOMEM);
	}

	error = queue_enqueue(&queue, ctx->root_dir_cluster, false, 0, "/");
	if (error != 0) {
		free(upcase_table);
		free(visited_bitmap);
		queue_free(&queue);
		return (error);
	}

	while (queue_dequeue(&queue, &item)) {
		error = dump_single_directory(ctx, item.cluster, item.path,
		    item.no_fat_chain, item.data_len, match_target, stats,
		    &queue, visited_bitmap, upcase_table, &target_found,
		    verbose);
		if (error != 0)
			stats->anomalies_count++;
	}

	free(upcase_table);
	free(visited_bitmap);
	queue_free(&queue);

	if (match_target == NULL) {
		if (stats->bitmap_count < ctx->num_fats)
			stats->anomalies_count++;
		if (stats->upcase_count == 0)
			stats->anomalies_count++;
	}

	if (match_target != NULL && !target_found)
		return (ENOENT);

	return (0);
}

/*
 * Dump directory entries, entry sets, and attributes (Spec §6.3, §7.4).
 */
int
util_dump_dentries(struct faultgen_ctx *ctx, const char *arg)
{
	struct dentry_stats stats;
	int error;

	error = dentry_scan_tree(ctx, arg, &stats, !ctx->json);
	if (error != 0)
		return (error);

	if (ctx->json) {
		printf("{\n");
		printf("  \"dentries_summary\": {\n");
		printf("    \"directories\": %zu,\n", stats.dir_count);
		printf("    \"files\": %zu,\n", stats.file_count);
		printf("    \"entry_sets\": %zu,\n", stats.entry_set_count);
		printf("    \"subdirectories\": %zu,\n", stats.subdir_count);
		printf("    \"checksum_mismatches\": %zu,\n",
		    stats.csum_mismatch_count);
		printf("    \"hash_mismatches\": %zu,\n",
		    stats.hash_mismatch_count);
		printf("    \"orphaned_secondaries\": %zu,\n",
		    stats.orphaned_secondary_count);
		printf("    \"anomalies\": %zu\n", stats.anomalies_count);
		printf("  }\n");
		printf("}\n");
		return (0);
	}

	print_dentry_summary(&stats);
	return (0);
}

/*
 * Locate the Up-case Table directory entry in the root directory (Spec §7.2).
 */
int
upcase_find_entry(struct faultgen_ctx *ctx, struct upcase_info *info)
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
			if (dentries[i].type == EXFAT_ENTRY_EOD) {
				free(cbuf);
				return (ENOENT);
			}

			if (dentries[i].type != EXFAT_ENTRY_UPCASE)
				continue;

			info->first_cluster = le32toh(
			    dentries[i].upcase.uc_first_cluster);
			info->data_length = le64toh(
			    dentries[i].upcase.uc_data_length);
			info->table_checksum = le32toh(
			    dentries[i].upcase.uc_table_checksum);
			info->dentry_cluster = curr_cn;
			info->dentry_offset = i * sizeof(union exfat_dentry);
			free(cbuf);
			return (0);
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
 * Decompress an on-disk exFAT Up-case table into a flat 65,536-entry array per
 * Specification §7.2.
 *
 * Returns 0 on success, or EINVAL if raw_len is invalid, the stream is
 * truncated, an escape count is invalid, or the stream fails to define all
 * 65,536 characters.
 */
static int
decompress_upcase(const uint8_t *raw, size_t raw_len, uint16_t *table)
{
	size_t offset;
	uint32_t ch;

	if (raw == NULL || table == NULL || (raw_len & 1) != 0 ||
	    raw_len == 0 || raw_len > EXFAT_MAX_UPCASE_SIZE)
		return (EINVAL);

	for (uint32_t i = 0; i < EXFAT_UPCASE_TABLE_CHARS; i++)
		table[i] = (uint16_t)i;

	offset = 0;
	ch = 0;

	while (offset + sizeof(uint16_t) <= raw_len &&
	    ch < EXFAT_UPCASE_TABLE_CHARS) {
		uint16_t val = le16dec(&raw[offset]);

		offset += sizeof(uint16_t);
		if (val == EXFAT_UPCASE_COMPRESSED_FLAG) {
			uint16_t count;

			if (offset + sizeof(uint16_t) > raw_len) {
				if (ch == EXFAT_UPCASE_TABLE_CHARS - 1) {
					table[ch] = val;
					ch++;
					break;
				}
				return (EINVAL);
			}
			count = le16dec(&raw[offset]);
			offset += sizeof(uint16_t);

			if (count == 0 ||
			    ch + count > EXFAT_UPCASE_TABLE_CHARS)
				return (EINVAL);
			ch += count;
		} else {
			table[ch] = val;
			ch++;
		}
	}

	if (ch != EXFAT_UPCASE_TABLE_CHARS || offset != raw_len)
		return (EINVAL);

	return (0);
}

/*
 * Load and decompress the volume Up-case Table if valid (Spec §7.2).
 */
int
load_upcase_table(struct faultgen_ctx *ctx, uint16_t **table_out)
{
	struct upcase_info info;
	uint8_t *uc_buf;
	uint16_t *table;
	int error;

	if (ctx == NULL || table_out == NULL)
		return (EINVAL);

	*table_out = NULL;
	if (upcase_find_entry(ctx, &info) != 0)
		return (ENOENT);
	if (!exfat_cluster_is_valid(info.first_cluster, ctx->cluster_count) ||
	    info.data_length == 0 ||
	    info.data_length > EXFAT_MAX_UPCASE_SIZE ||
	    (info.data_length & 1) != 0)
		return (EINVAL);

	error = read_upcase_data(ctx, info.first_cluster,
	    (size_t)info.data_length, &uc_buf, NULL);
	if (error != 0)
		return (error);

	table = malloc(EXFAT_UPCASE_TABLE_CHARS * sizeof(*table));
	if (table == NULL) {
		free(uc_buf);
		return (ENOMEM);
	}
	if (decompress_upcase(uc_buf, (size_t)info.data_length, table) != 0) {
		free(table);
		free(uc_buf);
		return (EINVAL);
	}
	free(uc_buf);
	*table_out = table;
	return (0);
}
