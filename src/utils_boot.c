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
#include <sys/stat.h>

#include <err.h>
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

static int	check_region_checksum(struct faultgen_ctx *ctx,
		    uint64_t start_sec, uint32_t *calc_csum,
		    uint32_t *stored_csum, bool *valid);
static void	dump_boot_sector(const struct exfat_boot_sector *bs,
		    const char *title, uint32_t sector_num);
static void	compare_boot_sectors(const struct exfat_boot_sector *m,
		    const struct exfat_boot_sector *b);
static void	dump_checksum_summary(struct faultgen_ctx *ctx, bool show_main,
		    bool show_backup);

/*
 * Allocate a sector-sized buffer and read the specified boot sector.
 */
int
read_boot_sector(struct faultgen_ctx *ctx, uint64_t sector, uint8_t **buf_out)
{
	uint8_t *buf;
	int error;

	if (ctx == NULL || buf_out == NULL)
		return (EINVAL);

	buf = malloc(ctx->sector_size);
	if (buf == NULL)
		return (ENOMEM);

	error = read_sector(ctx, sector, buf);
	if (error != 0) {
		free(buf);
		return (error);
	}

	*buf_out = buf;
	return (0);
}

/*
 * Read sectors 0 to 10 of the specified boot region (0 for Main,
 * EXFAT_BACKUP_BOOT_SECTOR for Backup) and compute 32-bit boot checksum
 * per Spec §3.4.
 */
int
calc_boot_region_checksum(struct faultgen_ctx *ctx, uint64_t start_sec,
    uint32_t *csum_out)
{
	uint8_t *region_buf;
	size_t region_size;
	int error;

	if (ctx == NULL || csum_out == NULL)
		return (EINVAL);

	region_size = (size_t)ctx->sector_size * EXFAT_BOOT_SECTORS_CHECKSUM;
	region_buf = malloc(region_size);
	if (region_buf == NULL)
		return (ENOMEM);

	for (size_t i = 0; i < EXFAT_BOOT_SECTORS_CHECKSUM; i++) {
		error = read_sector(ctx, start_sec + i,
		    region_buf + (i * ctx->sector_size));
		if (error != 0) {
			free(region_buf);
			return (error);
		}
	}

	*csum_out = exfat_calc_boot_checksum(region_buf, ctx->sector_size);
	free(region_buf);
	return (0);
}

/*
 * Read 11 boot sectors of a region and compute 32-bit checksum, then read
 * Sector 11 and compare against stored checksum per Spec §3.4.
 */
static int
check_region_checksum(struct faultgen_ctx *ctx, uint64_t start_sec,
    uint32_t *calc_csum, uint32_t *stored_csum, bool *valid)
{
	uint8_t *csum_sec;
	int error;

	error = calc_boot_region_checksum(ctx, start_sec, calc_csum);
	if (error != 0)
		return (error);

	csum_sec = malloc(ctx->sector_size);
	if (csum_sec == NULL)
		return (ENOMEM);

	error = read_sector(ctx, start_sec + EXFAT_BOOT_CHECKSUM_SECTOR,
	    csum_sec);
	if (error != 0) {
		free(csum_sec);
		return (error);
	}

	*stored_csum = le32dec(csum_sec);
	*valid = exfat_verify_boot_checksum_sector(csum_sec, ctx->sector_size,
	    *calc_csum);
	free(csum_sec);

	return (0);
}

/*
 * Dump formatted boot sector parameters per Spec §3.1.
 */
static void
dump_boot_sector(const struct exfat_boot_sector *bs, const char *title,
    uint32_t sector_num)
{
	char size_buf[32];
	uint64_t vol_len_bytes, vol_len_sec;
	uint32_t cluster_size, root_dir_cn, sector_size;
	uint16_t rev, sig, vol_flags;
	uint8_t sec_shift, spc_shift;

	sec_shift = bs->bs_bytes_per_sector_shift;
	spc_shift = bs->bs_sectors_per_cluster_shift;
	sector_size = (sec_shift <= EXFAT_MAX_SECTOR_SHIFT) ?
	    (1U << sec_shift) : 0;
	cluster_size = (sec_shift + spc_shift <= EXFAT_MAX_CLUSTER_SHIFT) ?
	    (1U << (sec_shift + spc_shift)) : 0;

	vol_len_sec = le64toh(bs->bs_volume_length);
	vol_len_bytes = (sec_shift <= EXFAT_MAX_SECTOR_SHIFT) ?
	    (vol_len_sec << sec_shift) : 0;
	format_bytes(vol_len_bytes, size_buf, sizeof(size_buf));

	rev = le16toh(bs->bs_fs_revision);
	vol_flags = le16toh(bs->bs_volume_flags);
	sig = le16toh(bs->bs_boot_signature);
	root_dir_cn = le32toh(bs->bs_root_dir_cluster);

	printf("%s (Sector %" PRIu32 ", Spec §3.1):\n", title, sector_num);
	printf("  File System Name:          \"%.8s\"\n", bs->bs_fs_name);
	printf("  File System Revision:      %u.%02u (0x%04" PRIx16 ")\n",
	    rev >> 8, rev & 0xFF, rev);
	printf("  Volume Serial Number:      %04" PRIX32 "-%04" PRIX32
	    " (0x%08" PRIX32 ")\n",
	    le32toh(bs->bs_volume_serial) >> 16,
	    le32toh(bs->bs_volume_serial) & 0xFFFF,
	    le32toh(bs->bs_volume_serial));
	printf("  Partition Offset:          %" PRIu64 " sectors\n",
	    le64toh(bs->bs_partition_offset));
	printf("  Volume Length:             %" PRIu64 " sectors (%s)\n",
	    vol_len_sec, size_buf);
	printf("  Bytes Per Sector Shift:    %" PRIu8 " (%u bytes)\n",
	    sec_shift, sector_size);
	printf("  Sectors Per Cluster Shift: %" PRIu8 " (%u sectors, "
	    "%u bytes/cluster)\n",
	    spc_shift,
	    (spc_shift <= EXFAT_MAX_CLUSTER_SHIFT) ? (1U << spc_shift) : 0,
	    cluster_size);
	printf("  Number of FATs:            %" PRIu8 "%s\n",
	    bs->bs_number_of_fats,
	    bs->bs_number_of_fats == 2 ? " (TexFAT)" : "");
	printf("  Drive Select:              0x%02" PRIX8 "%s\n",
	    bs->bs_drive_select,
	    bs->bs_drive_select == 0x80 ? " (Hard Disk)" :
	    bs->bs_drive_select == 0x00 ? " (Floppy)" : "");
	if (bs->bs_percent_in_use == 0xFF)
		printf("  Percent In Use:            0xFF (Not available)\n");
	else
		printf("  Percent In Use:            %" PRIu8 "%%\n",
		    bs->bs_percent_in_use);

	printf("\n  Volume Flags:              0x%04" PRIx16 "\n", vol_flags);
	printf("    Active FAT:              FAT %u\n",
	    (vol_flags & EXFAT_VOL_ACTIVE_FAT) ? 1 : 0);
	printf("    Volume State:            %s\n",
	    (vol_flags & EXFAT_VOL_DIRTY) ? "Dirty" : "Clean");
	printf("    Media Failure:           %s\n",
	    (vol_flags & EXFAT_VOL_MEDIA_FAILURE) ?
	    "Failure Detected" : "Normal");
	printf("    Clear To Zero:           %s\n",
	    (vol_flags & EXFAT_VOL_CLEAR_TO_ZERO) ? "Required" : "No");

	printf("\n  Volume Layout:\n");
	printf("    FAT Offset:              Sector %" PRIu32
	    " (Offset 0x%" PRIx64 ")\n",
	    le32toh(bs->bs_fat_offset),
	    (sec_shift <= EXFAT_MAX_SECTOR_SHIFT) ?
	    ((uint64_t)le32toh(bs->bs_fat_offset) << sec_shift) : 0);
	printf("    FAT Length:              %" PRIu32 " sectors\n",
	    le32toh(bs->bs_fat_length));
	printf("    Cluster Heap Offset:     Sector %" PRIu32
	    " (Offset 0x%" PRIx64 ")\n",
	    le32toh(bs->bs_cluster_heap_offset),
	    (sec_shift <= EXFAT_MAX_SECTOR_SHIFT) ?
	    ((uint64_t)le32toh(bs->bs_cluster_heap_offset) << sec_shift) : 0);
	printf("    Cluster Count:           %" PRIu32 " clusters\n",
	    le32toh(bs->bs_cluster_count));
	printf("    Root Directory Cluster:  Cluster %" PRIu32 "\n",
	    root_dir_cn);
	printf("  Boot Signature:            0x%04" PRIX16 " (%s)\n",
	    sig, sig == EXFAT_BOOT_SIGNATURE ? "VALID" : "INVALID");
}

/*
 * Compare Main Boot Sector against Backup Boot Sector per Spec §3.1.
 */
static void
compare_boot_sectors(const struct exfat_boot_sector *m,
    const struct exfat_boot_sector *b)
{
	int diffs = 0;

	printf("\nBoot Sector Comparison (Main vs Backup, Spec §3.1):\n");
	if (memcmp(m, b, sizeof(struct exfat_boot_sector)) == 0) {
		printf("  Main and Backup Boot Sectors are identical "
		    "(IN SYNC)\n");
		return;
	}

	printf("  MISMATCH detected between Main and Backup Boot Sectors:\n");
	if (memcmp(m->bs_jmp_boot, b->bs_jmp_boot,
	    sizeof(m->bs_jmp_boot)) != 0) {
		printf("    Jump Boot:            Main != Backup\n");
		diffs++;
	}
	if (memcmp(m->bs_fs_name, b->bs_fs_name, sizeof(m->bs_fs_name)) != 0) {
		printf("    FS Name:              Main (\"%.8s\") != "
		    "Backup (\"%.8s\")\n", m->bs_fs_name, b->bs_fs_name);
		diffs++;
	}
	if (m->bs_volume_length != b->bs_volume_length) {
		printf("    Volume Length:        Main (%" PRIu64
		    ") != Backup (%" PRIu64 ")\n",
		    le64toh(m->bs_volume_length), le64toh(b->bs_volume_length));
		diffs++;
	}
	if (m->bs_fat_offset != b->bs_fat_offset) {
		printf("    FAT Offset:           Main (%" PRIu32
		    ") != Backup (%" PRIu32 ")\n",
		    le32toh(m->bs_fat_offset), le32toh(b->bs_fat_offset));
		diffs++;
	}
	if (m->bs_fat_length != b->bs_fat_length) {
		printf("    FAT Length:           Main (%" PRIu32
		    ") != Backup (%" PRIu32 ")\n",
		    le32toh(m->bs_fat_length), le32toh(b->bs_fat_length));
		diffs++;
	}
	if (m->bs_cluster_heap_offset != b->bs_cluster_heap_offset) {
		printf("    Cluster Heap Offset:  Main (%" PRIu32
		    ") != Backup (%" PRIu32 ")\n",
		    le32toh(m->bs_cluster_heap_offset),
		    le32toh(b->bs_cluster_heap_offset));
		diffs++;
	}
	if (m->bs_cluster_count != b->bs_cluster_count) {
		printf("    Cluster Count:        Main (%" PRIu32
		    ") != Backup (%" PRIu32 ")\n",
		    le32toh(m->bs_cluster_count), le32toh(b->bs_cluster_count));
		diffs++;
	}
	if (m->bs_root_dir_cluster != b->bs_root_dir_cluster) {
		printf("    Root Dir Cluster:     Main (%" PRIu32
		    ") != Backup (%" PRIu32 ")\n",
		    le32toh(m->bs_root_dir_cluster),
		    le32toh(b->bs_root_dir_cluster));
		diffs++;
	}
	if (m->bs_volume_serial != b->bs_volume_serial) {
		printf("    Volume Serial:        Main (0x%08" PRIX32
		    ") != Backup (0x%08" PRIX32 ")\n",
		    le32toh(m->bs_volume_serial), le32toh(b->bs_volume_serial));
		diffs++;
	}
	if (m->bs_volume_flags != b->bs_volume_flags) {
		printf("    Volume Flags:         Main (0x%04" PRIx16
		    ") != Backup (0x%04" PRIx16 ")\n",
		    le16toh(m->bs_volume_flags), le16toh(b->bs_volume_flags));
		diffs++;
	}
	if (m->bs_bytes_per_sector_shift != b->bs_bytes_per_sector_shift) {
		printf("    Sector Shift:         Main (%" PRIu8
		    ") != Backup (%" PRIu8 ")\n",
		    m->bs_bytes_per_sector_shift, b->bs_bytes_per_sector_shift);
		diffs++;
	}
	if (m->bs_sectors_per_cluster_shift !=
	    b->bs_sectors_per_cluster_shift) {
		printf("    Cluster Shift:        Main (%" PRIu8
		    ") != Backup (%" PRIu8 ")\n",
		    m->bs_sectors_per_cluster_shift,
		    b->bs_sectors_per_cluster_shift);
		diffs++;
	}
	if (m->bs_number_of_fats != b->bs_number_of_fats) {
		printf("    Number of FATs:       Main (%" PRIu8
		    ") != Backup (%" PRIu8 ")\n",
		    m->bs_number_of_fats, b->bs_number_of_fats);
		diffs++;
	}
	if (m->bs_fs_revision != b->bs_fs_revision) {
		printf("    FS Revision:          Main (0x%04" PRIx16
		    ") != Backup (0x%04" PRIx16 ")\n",
		    le16toh(m->bs_fs_revision), le16toh(b->bs_fs_revision));
		diffs++;
	}
	if (m->bs_partition_offset != b->bs_partition_offset) {
		printf("    Partition Offset:     Main (%" PRIu64
		    ") != Backup (%" PRIu64 ")\n",
		    le64toh(m->bs_partition_offset),
		    le64toh(b->bs_partition_offset));
		diffs++;
	}
	if (m->bs_drive_select != b->bs_drive_select) {
		printf("    Drive Select:         Main (0x%02" PRIX8
		    ") != Backup (0x%02" PRIX8 ")\n",
		    m->bs_drive_select, b->bs_drive_select);
		diffs++;
	}
	if (m->bs_percent_in_use != b->bs_percent_in_use) {
		printf("    Percent In Use:       Main (0x%02" PRIX8
		    ") != Backup (0x%02" PRIX8 ")\n",
		    m->bs_percent_in_use, b->bs_percent_in_use);
		diffs++;
	}
	if (m->bs_boot_signature != b->bs_boot_signature) {
		printf("    Boot Signature:       Main (0x%04" PRIX16
		    ") != Backup (0x%04" PRIX16 ")\n",
		    le16toh(m->bs_boot_signature),
		    le16toh(b->bs_boot_signature));
		diffs++;
	}
	if (diffs == 0)
		printf("    Boot code or reserved fields differ\n");
}

/*
 * Verify and print 32-bit checksums for Main and Backup boot regions.
 */
static void
dump_checksum_summary(struct faultgen_ctx *ctx, bool show_main,
    bool show_backup)
{
	uint32_t calc_csum, stored_csum;
	bool valid;
	int error;

	printf("\nBoot Checksum Verification (Spec §3.4):\n");
	if (show_main) {
		error = check_region_checksum(ctx, 0, &calc_csum,
		    &stored_csum, &valid);
		if (error == 0)
			printf("  Main Boot Region:   Calculated: 0x%08" PRIX32
			    ", Stored: 0x%08" PRIX32 " [%s]\n",
			    calc_csum, stored_csum,
			    valid ? "VALID" : "INVALID");
		else
			printf("  Main Boot Region:   I/O error (%s)\n",
			    strerror(error));
	}
	if (show_backup) {
		error = check_region_checksum(ctx, EXFAT_BACKUP_BOOT_SECTOR,
		    &calc_csum, &stored_csum, &valid);
		if (error == 0)
			printf("  Backup Boot Region: Calculated: 0x%08" PRIX32
			    ", Stored: 0x%08" PRIX32 " [%s]\n",
			    calc_csum, stored_csum,
			    valid ? "VALID" : "INVALID");
		else
			printf("  Backup Boot Region: I/O error (%s)\n",
			    strerror(error));
	}
}

/*
 * Read a boot sector into a caller-supplied struct exfat_boot_sector.
 */
static int
read_boot_sector_struct(struct faultgen_ctx *ctx, uint64_t sector,
    struct exfat_boot_sector *bs_out)
{
	uint8_t *sec_buf;
	int error;

	error = read_boot_sector(ctx, sector, &sec_buf);
	if (error != 0)
		return (error);
	memcpy(bs_out, sec_buf, sizeof(*bs_out));
	free(sec_buf);
	return (0);
}

/*
 * Perform verification of boot region parameters and checksums
 * (Spec §3.1, §3.4).
 */
int
boot_verify(struct faultgen_ctx *ctx, struct boot_verify_stats *stats)
{
	struct exfat_boot_sector backup_bs, main_bs;
	struct stat sb;
	uint64_t heap_sectors, min_fat_sectors, volume_length;
	uint32_t calc_csum, cluster_count, cluster_heap_offset, fat_length;
	uint32_t fat_offset, root_dir_cluster, sector_size, stored_csum;
	int error;

	memset(stats, 0, sizeof(*stats));

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = read_boot_sector_struct(ctx, 0, &main_bs);
	if (error != 0)
		return (error);

	if (main_bs.bs_bytes_per_sector_shift < EXFAT_MIN_SECTOR_SHIFT ||
	    main_bs.bs_bytes_per_sector_shift > EXFAT_MAX_SECTOR_SHIFT)
		stats->param_errors++;
	if (main_bs.bs_sectors_per_cluster_shift >
	    (EXFAT_MAX_CLUSTER_SHIFT - main_bs.bs_bytes_per_sector_shift))
		stats->param_errors++;
	if (main_bs.bs_number_of_fats != 1 && main_bs.bs_number_of_fats != 2)
		stats->param_errors++;
	if (le16toh(main_bs.bs_boot_signature) != EXFAT_BOOT_SIGNATURE)
		stats->param_errors++;
	if (main_bs.bs_jmp_boot[0] != EXFAT_BOOT_JMP_0 ||
	    main_bs.bs_jmp_boot[1] != EXFAT_BOOT_JMP_1 ||
	    main_bs.bs_jmp_boot[2] != EXFAT_BOOT_JMP_2)
		stats->param_errors++;
	if (memcmp(main_bs.bs_fs_name, EXFAT_FS_NAME,
	    sizeof(main_bs.bs_fs_name)) != 0)
		stats->param_errors++;
	if ((le16toh(main_bs.bs_fs_revision) >> 8) != EXFAT_FS_REVISION_MAJOR)
		stats->param_errors++;
	if ((le16toh(main_bs.bs_volume_flags) & 0xFFF0) != 0)
		stats->param_errors++;
	if (main_bs.bs_number_of_fats == 1 &&
	    (le16toh(main_bs.bs_volume_flags) & EXFAT_VOL_ACTIVE_FAT) != 0)
		stats->param_errors++;
	if ((le16toh(main_bs.bs_volume_flags) & EXFAT_VOL_CLEAR_TO_ZERO) != 0)
		stats->param_errors++;
	if (main_bs.bs_percent_in_use > 100 &&
	    main_bs.bs_percent_in_use != EXFAT_PERCENT_IN_USE_UNKNOWN)
		stats->param_errors++;
	if (main_bs.bs_drive_select != 0x00 &&
	    main_bs.bs_drive_select != EXFAT_DRIVE_SELECT_HD)
		stats->param_errors++;
	if (!is_all_zero(main_bs.bs_must_be_zero,
	    sizeof(main_bs.bs_must_be_zero)))
		stats->param_errors++;
	if (!is_all_zero(main_bs.bs_reserved, sizeof(main_bs.bs_reserved)))
		stats->param_errors++;

	fat_offset = le32toh(main_bs.bs_fat_offset);
	fat_length = le32toh(main_bs.bs_fat_length);
	cluster_heap_offset = le32toh(main_bs.bs_cluster_heap_offset);
	cluster_count = le32toh(main_bs.bs_cluster_count);
	root_dir_cluster = le32toh(main_bs.bs_root_dir_cluster);
	volume_length = le64toh(main_bs.bs_volume_length);
	sector_size = (main_bs.bs_bytes_per_sector_shift >=
	    EXFAT_MIN_SECTOR_SHIFT && main_bs.bs_bytes_per_sector_shift <=
	    EXFAT_MAX_SECTOR_SHIFT) ?
	    (1U << main_bs.bs_bytes_per_sector_shift) :
	    (1U << EXFAT_MIN_SECTOR_SHIFT);

	if (fat_offset < EXFAT_MIN_FAT_OFFSET)
		stats->param_errors++;
	if (cluster_heap_offset < (uint64_t)fat_offset +
	    (uint64_t)main_bs.bs_number_of_fats * fat_length)
		stats->param_errors++;
	if (cluster_count < 1 || cluster_count > EXFAT_MAX_CLUSTER_COUNT)
		stats->param_errors++;
	if (!exfat_cluster_is_valid(root_dir_cluster, cluster_count))
		stats->param_errors++;
	if (main_bs.bs_bytes_per_sector_shift <= EXFAT_MAX_SECTOR_SHIFT &&
	    volume_length < (EXFAT_MIN_VOLUME_SIZE >>
	    main_bs.bs_bytes_per_sector_shift))
		stats->param_errors++;
	if (main_bs.bs_sectors_per_cluster_shift <= EXFAT_MAX_CLUSTER_SHIFT) {
		heap_sectors = (uint64_t)cluster_count <<
		    main_bs.bs_sectors_per_cluster_shift;
		if ((uint64_t)cluster_heap_offset + heap_sectors >
		    volume_length)
			stats->param_errors++;
	}
	if (fstat(ctx->fd, &sb) == 0 && S_ISREG(sb.st_mode) &&
	    sb.st_size > 0 &&
	    main_bs.bs_bytes_per_sector_shift <= EXFAT_MAX_SECTOR_SHIFT &&
	    volume_length > ((uint64_t)sb.st_size >>
	    main_bs.bs_bytes_per_sector_shift))
		stats->param_errors++;
	min_fat_sectors = howmany(((uint64_t)cluster_count + 2) *
	    sizeof(uint32_t), sector_size);
	if (fat_length < min_fat_sectors)
		stats->param_errors++;

	error = check_region_checksum(ctx, 0, &calc_csum, &stored_csum,
	    &stats->main_valid);
	if (error != 0)
		return (error);

	error = read_boot_sector_struct(ctx, EXFAT_BACKUP_BOOT_SECTOR,
	    &backup_bs);
	if (error != 0)
		return (error);

	error = check_region_checksum(ctx, EXFAT_BACKUP_BOOT_SECTOR,
	    &calc_csum, &stored_csum, &stats->backup_valid);
	if (error != 0)
		return (error);

	stats->backup_matches_main = (memcmp(&main_bs, &backup_bs,
	    sizeof(main_bs)) == 0);

	return (0);
}

/*
 * Dump Boot Sector parameters and verify boot checksums (Spec §3.1, §3.4).
 */
int
util_dump_boot(struct faultgen_ctx *ctx, const char *arg)
{
	struct exfat_boot_sector backup_bs, main_bs;
	int error;
	bool do_backup, do_main;

	if (arg == NULL || *arg == '\0' || strcmp(arg, "all") == 0 ||
	    strcmp(arg, "both") == 0) {
		do_main = true;
		do_backup = true;
	} else if (strcmp(arg, "main") == 0) {
		do_main = true;
		do_backup = false;
	} else if (strcmp(arg, "backup") == 0) {
		do_main = false;
		do_backup = true;
	} else {
		warnx("invalid boot region '%s'; expected 'main' or 'backup'",
		    arg);
		return (EINVAL);
	}

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	if (ctx->json) {
		struct boot_verify_stats vstats;

		error = boot_verify(ctx, &vstats);
		if (error != 0)
			return (error);

		printf("{\n");
		printf("  \"boot_sector\": {\n");
		printf("    \"fs_name\": ");
		print_json_string((const char *)ctx->bs.bs_fs_name,
		    sizeof(ctx->bs.bs_fs_name));
		printf(",\n");
		printf("    \"volume_serial\": \"0x%08" PRIX32 "\",\n",
		    le32toh(ctx->bs.bs_volume_serial));
		printf("    \"sector_size\": %u,\n", ctx->sector_size);
		printf("    \"cluster_size\": %u,\n", ctx->cluster_size);
		printf("    \"cluster_count\": %" PRIu32 ",\n",
		    ctx->cluster_count);
		printf("    \"number_of_fats\": %u,\n", ctx->num_fats);
		printf("    \"main_checksum_valid\": %s,\n",
		    vstats.main_valid ? "true" : "false");
		printf("    \"backup_matches_main\": %s,\n",
		    vstats.backup_matches_main ? "true" : "false");
		printf("    \"backup_checksum_valid\": %s\n",
		    vstats.backup_valid ? "true" : "false");
		printf("  }\n");
		printf("}\n");
		return (0);
	}

	if (do_main) {
		error = read_boot_sector_struct(ctx, 0, &main_bs);
		if (error != 0)
			return (error);
		dump_boot_sector(&main_bs, "Main Boot Sector", 0);
	}

	if (do_backup) {
		error = read_boot_sector_struct(ctx, EXFAT_BACKUP_BOOT_SECTOR,
		    &backup_bs);
		if (error != 0)
			return (error);
		if (!do_main)
			dump_boot_sector(&backup_bs, "Backup Boot Sector",
			    EXFAT_BACKUP_BOOT_SECTOR);
	}

	if (do_main && do_backup)
		compare_boot_sectors(&main_bs, &backup_bs);

	dump_checksum_summary(ctx, do_main, do_backup);

	return (0);
}
