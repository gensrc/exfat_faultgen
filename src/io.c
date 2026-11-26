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
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "faultgen.h"
#include "io.h"

static int	fat_entry_location(const struct faultgen_ctx *ctx,
		    uint8_t fat_idx, uint32_t cn, uint64_t *target_sec,
		    uint32_t *entry_in_sec);

/*
 * Validate whether a boot sector contains valid jump instructions, filesystem
 * name, and boot signature per Spec §3.1.
 */
static bool
boot_sector_is_valid(const struct exfat_boot_sector *bs)
{
	if (bs == NULL)
		return (false);

	if (bs->bs_jmp_boot[0] != EXFAT_BOOT_JMP_0 ||
	    bs->bs_jmp_boot[1] != EXFAT_BOOT_JMP_1 ||
	    bs->bs_jmp_boot[2] != EXFAT_BOOT_JMP_2 ||
	    memcmp(bs->bs_fs_name, EXFAT_FS_NAME,
	    sizeof(bs->bs_fs_name)) != 0 ||
	    le16toh(bs->bs_boot_signature) != EXFAT_BOOT_SIGNATURE)
		return (false);

	if (bs->bs_bytes_per_sector_shift < EXFAT_MIN_SECTOR_SHIFT ||
	    bs->bs_bytes_per_sector_shift > EXFAT_MAX_SECTOR_SHIFT ||
	    bs->bs_sectors_per_cluster_shift > EXFAT_MAX_CLUSTER_SHIFT ||
	    (bs->bs_bytes_per_sector_shift + bs->bs_sectors_per_cluster_shift) >
	    EXFAT_MAX_CLUSTER_SHIFT)
		return (false);

	return (true);
}

/*
 * Open the target image file and load volume geometry from the boot sector.
 *
 * Validates the primary Volume Boot Record (VBR) per Spec §3.1. If the
 * primary VBR is invalid, attempts recovery of geometry from the Backup
 * VBR per Spec §3.1.
 */
int
open_image(struct faultgen_ctx *ctx, const char *path)
{
	uint8_t boot_buf[1U << EXFAT_MAX_SECTOR_SHIFT];
	ssize_t n;
	int flags;

	if (ctx == NULL || path == NULL)
		return (EINVAL);

	if (ctx->fd >= 0)
		close_image(ctx);

	ctx->image_path = path;
	flags = ctx->dry_run ? O_RDONLY : O_RDWR;
	ctx->fd = open(path, flags);
	if (ctx->fd < 0)
		return (errno);

	/*
	 * Read Sector 0 into a maximum-sector buffer to accommodate native
	 * 4Kn devices (where pread count must be a multiple of 4096 bytes).
	 * Fall back to sizeof(ctx->bs) if file size is less than 4096 bytes.
	 */
	n = pread(ctx->fd, boot_buf, sizeof(boot_buf), 0);
	if (n < (ssize_t)sizeof(ctx->bs)) {
		n = pread(ctx->fd, boot_buf, sizeof(ctx->bs), 0);
		if (n < (ssize_t)sizeof(ctx->bs)) {
			int err;

			err = (n < 0 ? errno : EIO);
			close(ctx->fd);
			ctx->fd = -1;
			return (err);
		}
	}
	memcpy(&ctx->bs, boot_buf, sizeof(ctx->bs));

	if (!boot_sector_is_valid(&ctx->bs)) {
		struct exfat_boot_sector bbs;
		bool backup_found;

		backup_found = false;
		for (int shift = EXFAT_MIN_SECTOR_SHIFT;
		    shift <= EXFAT_MAX_SECTOR_SHIFT; shift++) {
			off_t backup_offset;
			size_t read_size;

			backup_offset = (off_t)EXFAT_BACKUP_BOOT_SECTOR <<
			    shift;
			read_size = 1U << shift;
			n = pread(ctx->fd, boot_buf, read_size, backup_offset);
			if (n >= (ssize_t)sizeof(bbs)) {
				memcpy(&bbs, boot_buf, sizeof(bbs));
				if (boot_sector_is_valid(&bbs) &&
				    bbs.bs_bytes_per_sector_shift == shift) {
					ctx->bs = bbs;
					backup_found = true;
					break;
				}
			}
		}
		if (!backup_found) {
			close(ctx->fd);
			ctx->fd = -1;
			return (EINVAL);
		}
	}

	ctx->sector_shift = ctx->bs.bs_bytes_per_sector_shift;
	ctx->cluster_shift = ctx->bs.bs_sectors_per_cluster_shift;

	ctx->sector_size = (uint32_t)1 << ctx->sector_shift;
	ctx->cluster_size = (uint32_t)1 <<
	    (ctx->sector_shift + ctx->cluster_shift);
	ctx->fat_offset = le32toh(ctx->bs.bs_fat_offset);
	ctx->fat_length = le32toh(ctx->bs.bs_fat_length);
	ctx->cluster_heap_offset = le32toh(ctx->bs.bs_cluster_heap_offset);
	ctx->cluster_count = le32toh(ctx->bs.bs_cluster_count);
	ctx->root_dir_cluster = le32toh(ctx->bs.bs_root_dir_cluster);
	ctx->volume_flags = le16toh(ctx->bs.bs_volume_flags);
	ctx->num_fats = ctx->bs.bs_number_of_fats;

	if (ctx->fat_offset < EXFAT_MIN_FAT_OFFSET ||
	    ctx->fat_length == 0 ||
	    (ctx->num_fats != 1 && ctx->num_fats != 2) ||
	    ctx->cluster_heap_offset < (uint64_t)ctx->fat_offset +
	    ((uint64_t)ctx->num_fats * ctx->fat_length) ||
	    ctx->cluster_count == 0 ||
	    ctx->cluster_count > EXFAT_MAX_CLUSTER_COUNT ||
	    !exfat_cluster_is_valid(ctx->root_dir_cluster,
	    ctx->cluster_count)) {
		close(ctx->fd);
		ctx->fd = -1;
		return (EINVAL);
	}

	if (ctx->verbose && !ctx->json)
		printf("Image opened: %s (sector_size=%u, cluster_size=%u, "
		    "clusters=%u)\n", path, ctx->sector_size,
		    ctx->cluster_size, ctx->cluster_count);

	return (0);
}

/*
 * Close target image file and reset descriptor.
 */
void
close_image(struct faultgen_ctx *ctx)
{
	if (ctx == NULL || ctx->fd < 0)
		return;

	close(ctx->fd);
	ctx->fd = -1;
}

/*
 * Flush pending writes to storage.
 */
int
sync_image(struct faultgen_ctx *ctx)
{
	if (ctx == NULL || ctx->fd < 0)
		return (EINVAL);

	if (ctx->dry_run)
		return (0);

	if (fsync(ctx->fd) != 0)
		return (errno);

	return (0);
}

/*
 * Read sector from image.
 */
int
read_sector(struct faultgen_ctx *ctx, uint64_t sector, void *buf)
{
	off_t offset;
	ssize_t n;

	if (ctx == NULL || ctx->fd < 0 || buf == NULL || ctx->sector_size == 0)
		return (EINVAL);

	offset = (off_t)sector << ctx->sector_shift;
	n = pread(ctx->fd, buf, ctx->sector_size, offset);
	if (n < (ssize_t)ctx->sector_size)
		return (n < 0 ? errno : EIO);

	return (0);
}

/*
 * Write sector to image.
 */
int
write_sector(struct faultgen_ctx *ctx, uint64_t sector, const void *buf)
{
	off_t offset;
	ssize_t n;

	if (ctx == NULL || ctx->fd < 0 || buf == NULL || ctx->sector_size == 0)
		return (EINVAL);

	if (ctx->dry_run) {
		if (ctx->verbose)
			printf("[dry-run] write_sector: sector %" PRIu64 "\n",
			    sector);
		return (0);
	}

	offset = (off_t)sector << ctx->sector_shift;
	n = pwrite(ctx->fd, buf, ctx->sector_size, offset);
	if (n < (ssize_t)ctx->sector_size)
		return (n < 0 ? errno : EIO);

	return (0);
}

/*
 * Read cluster from cluster heap.
 */
int
read_cluster(struct faultgen_ctx *ctx, uint32_t cn, void *buf)
{
	uint64_t sector;
	off_t offset;
	ssize_t n;

	if (ctx == NULL || ctx->fd < 0 || buf == NULL ||
	    ctx->cluster_size == 0)
		return (EINVAL);
	if (!exfat_cluster_is_valid(cn, ctx->cluster_count))
		return (EINVAL);

	sector = exfat_cluster_to_sector(ctx->cluster_heap_offset,
	    ctx->cluster_shift, cn);
	offset = (off_t)sector << ctx->sector_shift;
	n = pread(ctx->fd, buf, ctx->cluster_size, offset);
	if (n < (ssize_t)ctx->cluster_size)
		return (n < 0 ? errno : EIO);

	return (0);
}

/*
 * Write cluster to cluster heap.
 */
int
write_cluster(struct faultgen_ctx *ctx, uint32_t cn, const void *buf)
{
	uint64_t sector;
	off_t offset;
	ssize_t n;

	if (ctx == NULL || ctx->fd < 0 || buf == NULL ||
	    ctx->cluster_size == 0)
		return (EINVAL);
	if (!exfat_cluster_is_valid(cn, ctx->cluster_count))
		return (EINVAL);

	if (ctx->dry_run) {
		if (ctx->verbose)
			printf("[dry-run] write_cluster: cluster %" PRIu32 "\n",
			    cn);
		return (0);
	}

	sector = exfat_cluster_to_sector(ctx->cluster_heap_offset,
	    ctx->cluster_shift, cn);
	offset = (off_t)sector << ctx->sector_shift;
	n = pwrite(ctx->fd, buf, ctx->cluster_size, offset);
	if (n < (ssize_t)ctx->cluster_size)
		return (n < 0 ? errno : EIO);

	return (0);
}

/*
 * Validate FAT entry coordinates and compute on-disk sector and entry index.
 */
static int
fat_entry_location(const struct faultgen_ctx *ctx, uint8_t fat_idx,
    uint32_t cn, uint64_t *target_sec, uint32_t *entry_in_sec)
{
	uint64_t fat_sec, max_entries;
	uint32_t entries_per_sec;

	if (ctx == NULL || ctx->fd < 0 || ctx->sector_size == 0 ||
	    ctx->sector_size > (1U << EXFAT_MAX_SECTOR_SHIFT) ||
	    fat_idx >= ctx->num_fats)
		return (EINVAL);

	max_entries = ((uint64_t)ctx->fat_length << ctx->sector_shift) /
	    sizeof(uint32_t);
	if (cn >= max_entries)
		return (EINVAL);

	entries_per_sec = ctx->sector_size / sizeof(uint32_t);
	fat_sec = (uint64_t)ctx->fat_offset +
	    ((uint64_t)fat_idx * ctx->fat_length);
	*target_sec = fat_sec + (cn / entries_per_sec);
	*entry_in_sec = cn % entries_per_sec;
	return (0);
}

/*
 * Read entry from specified File Allocation Table (FAT 0 or FAT 1).
 */
int
fat_get_entry(struct faultgen_ctx *ctx, uint8_t fat_idx, uint32_t cn,
    uint32_t *val)
{
	uint8_t sec_buf[1U << EXFAT_MAX_SECTOR_SHIFT];
	uint64_t target_sec;
	uint32_t entry_in_sec;
	int error;

	if (val == NULL)
		return (EINVAL);

	error = fat_entry_location(ctx, fat_idx, cn, &target_sec,
	    &entry_in_sec);
	if (error != 0)
		return (error);

	error = read_sector(ctx, target_sec, sec_buf);
	if (error != 0)
		return (error);

	*val = le32dec(sec_buf + entry_in_sec * sizeof(uint32_t));
	return (0);
}

/*
 * Write entry to specified File Allocation Table (FAT 0 or FAT 1).
 */
int
fat_set_entry(struct faultgen_ctx *ctx, uint8_t fat_idx, uint32_t cn,
    uint32_t val)
{
	uint8_t sec_buf[1U << EXFAT_MAX_SECTOR_SHIFT];
	uint64_t target_sec;
	uint32_t entry_in_sec;
	int error;

	error = fat_entry_location(ctx, fat_idx, cn, &target_sec,
	    &entry_in_sec);
	if (error != 0)
		return (error);

	if (ctx->dry_run) {
		if (ctx->verbose)
			printf("[dry-run] fat_set_entry: FAT%u cluster %"
			    PRIu32 " -> 0x%08" PRIx32 "\n", fat_idx + 1, cn,
			    val);
		return (0);
	}

	error = read_sector(ctx, target_sec, sec_buf);
	if (error != 0)
		return (error);

	le32enc(sec_buf + entry_in_sec * sizeof(uint32_t), val);

	return (write_sector(ctx, target_sec, sec_buf));
}

/*
 * Read entry from the active File Allocation Table (Spec §3.1.13.1).
 */
int
fat_get(struct faultgen_ctx *ctx, uint32_t cn, uint32_t *val)
{
	if (ctx == NULL)
		return (EINVAL);

	return (fat_get_entry(ctx, exfat_active_fat(ctx), cn, val));
}

/*
 * Write entry to all File Allocation Tables in the volume (Spec §4.1).
 */
int
fat_set_all(struct faultgen_ctx *ctx, uint32_t cn, uint32_t val)
{
	int error;

	if (ctx == NULL)
		return (EINVAL);

	for (uint8_t i = 0; i < ctx->num_fats; i++) {
		error = fat_set_entry(ctx, i, cn, val);
		if (error != 0)
			return (error);
	}
	return (0);
}
