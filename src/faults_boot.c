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
#include <stdlib.h>

#include "faultgen.h"
#include "io.h"
#include "subr.h"

typedef void	(*boot_mutate_fn)(struct exfat_boot_sector *, const void *);

static int	update_boot_region_checksum(struct faultgen_ctx *ctx,
		    uint64_t start_sec);
static int	update_boot_sectors(struct faultgen_ctx *ctx,
		    boot_mutate_fn mutate, const void *arg,
		    bool update_checksum);
static void	mutate_flags_reserved(struct exfat_boot_sector *bs,
		    const void *arg);
static void	mutate_percent_in_use(struct exfat_boot_sector *bs,
		    const void *arg);
static void	mutate_drive_select(struct exfat_boot_sector *bs,
		    const void *arg);
static void	mutate_zero_fields(struct exfat_boot_sector *bs,
		    const void *arg);

/*
 * Recalculate 32-bit boot checksum across 11 sectors and write to Sector 11
 * of the specified boot region (0 for Main, EXFAT_BACKUP_BOOT_SECTOR for
 * Backup) per Spec §3.4.
 */
static int
update_boot_region_checksum(struct faultgen_ctx *ctx, uint64_t start_sec)
{
	uint8_t *csum_sec;
	uint32_t csum;
	int error;

	error = calc_boot_region_checksum(ctx, start_sec, &csum);
	if (error != 0)
		return (error);

	csum_sec = malloc(ctx->sector_size);
	if (csum_sec == NULL)
		return (ENOMEM);

	exfat_fill_boot_checksum_sector(csum_sec, ctx->sector_size, csum);

	error = write_sector(ctx, start_sec + EXFAT_BOOT_CHECKSUM_SECTOR,
	    csum_sec);
	free(csum_sec);

	return (error);
}

/*
 * Apply mutate to both Main and Backup Boot Sectors, optionally updating
 * Sector 11 checksums for both regions, then sync the image (Spec §3.1, §3.4).
 */
static int
update_boot_sectors(struct faultgen_ctx *ctx, boot_mutate_fn mutate,
    const void *arg, bool update_checksum)
{
	static const uint64_t sectors[2] = { 0, EXFAT_BACKUP_BOOT_SECTOR };
	uint8_t *sec_buf;
	int error;

	for (size_t i = 0; i < nitems(sectors); i++) {
		error = read_boot_sector(ctx, sectors[i], &sec_buf);
		if (error != 0)
			return (error);
		mutate((struct exfat_boot_sector *)sec_buf, arg);
		error = write_sector(ctx, sectors[i], sec_buf);
		free(sec_buf);
		if (error != 0)
			return (error);
	}

	if (update_checksum) {
		for (size_t i = 0; i < nitems(sectors); i++) {
			error = update_boot_region_checksum(ctx, sectors[i]);
			if (error != 0)
				return (error);
		}
	}

	return (sync_image(ctx));
}

static void
mutate_flags_reserved(struct exfat_boot_sector *bs, const void *arg)
{
	uint16_t mask = *(const uint16_t *)arg;

	bs->bs_volume_flags = htole16(le16toh(bs->bs_volume_flags) | mask);
}

static void
mutate_percent_in_use(struct exfat_boot_sector *bs, const void *arg)
{
	bs->bs_percent_in_use = *(const uint8_t *)arg;
}

static void
mutate_drive_select(struct exfat_boot_sector *bs, const void *arg)
{
	bs->bs_drive_select = *(const uint8_t *)arg;
}

static void
mutate_zero_fields(struct exfat_boot_sector *bs, const void *arg)
{
	(void)arg;
	bs->bs_must_be_zero[0] = 0x55;
	bs->bs_reserved[0] = 0xAA;
}

/*
 * Invalidate Sector 11 Main Boot checksum (Spec §3.4).
 */
int
fault_boot_checksum_mismatch(struct faultgen_ctx *ctx, const char *arg)
{
	uint8_t *sec_buf;
	int error;

	(void)arg;
	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	sec_buf = malloc(ctx->sector_size);
	if (sec_buf == NULL)
		return (ENOMEM);

	error = read_sector(ctx, EXFAT_BOOT_CHECKSUM_SECTOR, sec_buf);
	if (error != 0) {
		free(sec_buf);
		return (error);
	}

	/* Invert all bytes in Sector 11 to corrupt the checksum. */
	for (size_t i = 0; i < ctx->sector_size; i++)
		sec_buf[i] ^= 0xFF;

	error = write_sector(ctx, EXFAT_BOOT_CHECKSUM_SECTOR, sec_buf);
	free(sec_buf);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Mutate Main VBR without updating Backup VBR (Spec §3.1).
 */
int
fault_boot_backup_mismatch(struct faultgen_ctx *ctx, const char *arg)
{
	uint8_t *sec_buf;
	struct exfat_boot_sector *bs;
	int error;

	(void)arg;
	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	error = read_boot_sector(ctx, 0, &sec_buf);
	if (error != 0)
		return (error);

	/*
	 * Mutate volume serial number in Main Boot Sector.
	 * Recompute Sector 11 checksum so Main is internally valid, but
	 * differs from Backup.
	 */
	bs = (struct exfat_boot_sector *)sec_buf;
	bs->bs_volume_serial = htole32(le32toh(bs->bs_volume_serial) ^
	    0xA5A5A5A5U);

	error = write_sector(ctx, 0, sec_buf);
	free(sec_buf);
	if (error != 0)
		return (error);

	error = update_boot_region_checksum(ctx, 0);
	if (error != 0)
		return (error);

	return (sync_image(ctx));
}

/*
 * Set invalid reserved bits in VolumeFlags (Spec §3.1.13).
 */
int
fault_boot_flags_reserved(struct faultgen_ctx *ctx, const char *arg)
{
	uint16_t mask;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	mask = 0x0010;	/* Bit 4: first reserved bit per Spec §3.1.13 */
	if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) != 0 ||
		    (val & 0xFFF0) == 0 || val > 0xFFFF)
			return (EINVAL);
		mask = (uint16_t)(val & 0xFFF0);
	}

	/*
	 * VolumeFlags is excluded from boot checksum calculation per Spec
	 * §3.4, so no checksum recalculation is needed.
	 */
	return (update_boot_sectors(ctx, mutate_flags_reserved, &mask, false));
}

/*
 * Set invalid PercentInUse value (>100 and != 0xFF, Spec §3.1.18).
 */
int
fault_boot_percent_in_use(struct faultgen_ctx *ctx, const char *arg)
{
	uint8_t pct;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	pct = 150;	/* Invalid (> 100 and != 0xFF per Spec §3.1.18) */
	if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) != 0 ||
		    val <= 100 || val == EXFAT_PERCENT_IN_USE_UNKNOWN ||
		    val > 255)
			return (EINVAL);
		pct = (uint8_t)val;
	}

	/*
	 * PercentInUse is excluded from boot checksum calculation per Spec
	 * §3.4, so no checksum recalculation is needed.
	 */
	return (update_boot_sectors(ctx, mutate_percent_in_use, &pct, false));
}

/*
 * Set invalid DriveSelect value (!= 0x00 and != 0x80, Spec §3.1.17).
 */
int
fault_boot_drive_select(struct faultgen_ctx *ctx, const char *arg)
{
	uint8_t drive;
	int error;

	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	drive = 0x01;	/* Invalid (!= 0x00 and != 0x80 per Spec §3.1.17) */
	if (arg != NULL && *arg != '\0') {
		uint32_t val;

		if (parse_u32_str(arg, NULL, &val) != 0 ||
		    val == 0x00 || val == EXFAT_DRIVE_SELECT_HD || val > 255)
			return (EINVAL);
		drive = (uint8_t)val;
	}

	/*
	 * DriveSelect is included in boot checksum calculation, so update
	 * checksums for both regions to keep this fault orthogonal.
	 */
	return (update_boot_sectors(ctx, mutate_drive_select, &drive, true));
}

/*
 * Inject non-zero bytes in must_be_zero / reserved fields (Spec §3.1,
 * §3.1.3).
 */
int
fault_boot_zero_fields(struct faultgen_ctx *ctx, const char *arg)
{
	int error;

	(void)arg;
	error = ensure_image_open(ctx);
	if (error != 0)
		return (error);

	/*
	 * Both fields are covered by boot checksum, so update checksums for
	 * both regions to keep this fault orthogonal.
	 */
	return (update_boot_sectors(ctx, mutate_zero_fields, NULL, true));
}
