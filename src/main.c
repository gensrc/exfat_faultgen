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

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "faultgen.h"

enum {
	OPT_BOOT_CHECKSUM_MISMATCH = 256,
	OPT_BOOT_BACKUP_MISMATCH,
	OPT_BOOT_FLAGS_RESERVED,
	OPT_BOOT_PERCENT_IN_USE,
	OPT_BOOT_DRIVE_SELECT,
	OPT_BOOT_ZERO_FIELDS,
	OPT_FAT_CYCLE,
	OPT_FAT_BAD_CLUSTER,
	OPT_FAT_CROSSLINK,
	OPT_FAT_OUT_OF_BOUNDS,
	OPT_FAT_MIRROR_DIVERGE,
	OPT_BITMAP_ORPHAN,
	OPT_BITMAP_FALSE_FREE,
	OPT_BITMAP_TRUNCATE,
	OPT_BITMAP_MIRROR_DIVERGE,
	OPT_BITMAP_FLAGS_RESERVED,
	OPT_DENTRY_CHECKSUM,
	OPT_STREAM_VDL_EXCEEDS_DL,
	OPT_STREAM_NOFATCHAIN_FRAGMENT,
	OPT_DENTRY_ORPHANED_SECONDARY,
	OPT_DENTRY_ROOT_IN_SUBDIR,
	OPT_DENTRY_SECONDARY_COUNT,
	OPT_DENTRY_NAME_HASH,
	OPT_DENTRY_INVALID_NAME_CHARS,
	OPT_DENTRY_SIZE_MISMATCH,
	OPT_UPCASE_CHECKSUM_MISMATCH,
	OPT_UPCASE_TRUNCATE,
	OPT_LABEL_DUPLICATE,
	OPT_LABEL_INVALID_CHARS,
	OPT_LABEL_LENGTH,
	OPT_GUID_DUPLICATE,
	OPT_GUID_INVALID,
	OPT_DUMP_ALL,
	OPT_DUMP_BITMAP,
	OPT_DUMP_BOOT,
	OPT_DUMP_FAT,
	OPT_DUMP_DENTRIES,
	OPT_VERIFY,
};

static void	print_option_group(FILE *fp, bool utility);
static void	usage(int eval);

static const struct fault_handler fault_handlers[] = {
	{
		.opt_name = "boot-checksum-mismatch",
		.val = OPT_BOOT_CHECKSUM_MISMATCH,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Corrupt Sector 11 Main Boot checksum",
		.apply = fault_boot_checksum_mismatch,
	},
	{
		.opt_name = "boot-backup-mismatch",
		.val = OPT_BOOT_BACKUP_MISMATCH,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Mutate Main VBR without updating Backup VBR",
		.apply = fault_boot_backup_mismatch,
	},
	{
		.opt_name = "boot-flags-reserved",
		.val = OPT_BOOT_FLAGS_RESERVED,
		.has_arg = optional_argument,
		.arg_desc = "[mask]",
		.desc = "Set invalid reserved bits in VolumeFlags",
		.apply = fault_boot_flags_reserved,
	},
	{
		.opt_name = "boot-percent-in-use",
		.val = OPT_BOOT_PERCENT_IN_USE,
		.has_arg = optional_argument,
		.arg_desc = "[val]",
		.desc = "Set invalid PercentInUse (>100 and != 0xFF)",
		.apply = fault_boot_percent_in_use,
	},
	{
		.opt_name = "boot-drive-select",
		.val = OPT_BOOT_DRIVE_SELECT,
		.has_arg = optional_argument,
		.arg_desc = "[val]",
		.desc = "Set invalid DriveSelect (!= 0x00 and != 0x80)",
		.apply = fault_boot_drive_select,
	},
	{
		.opt_name = "boot-zero-fields",
		.val = OPT_BOOT_ZERO_FIELDS,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Inject non-zero bytes in must_be_zero/reserved fields",
		.apply = fault_boot_zero_fields,
	},
	{
		.opt_name = "fat-cycle",
		.val = OPT_FAT_CYCLE,
		.has_arg = required_argument,
		.arg_desc = "<cluster>",
		.desc = "Create a circular cluster cycle in FAT chain",
		.apply = fault_fat_cycle,
	},
	{
		.opt_name = "fat-bad-cluster",
		.val = OPT_FAT_BAD_CLUSTER,
		.has_arg = required_argument,
		.arg_desc = "<cluster>",
		.desc = "Mark an allocated cluster as EXFAT_FAT_BAD in FAT",
		.apply = fault_fat_bad_cluster,
	},
	{
		.opt_name = "fat-crosslink",
		.val = OPT_FAT_CROSSLINK,
		.has_arg = required_argument,
		.arg_desc = "<src,dst>",
		.desc = "Cross-link cluster chain into another file's chain",
		.apply = fault_fat_crosslink,
	},
	{
		.opt_name = "fat-out-of-bounds",
		.val = OPT_FAT_OUT_OF_BOUNDS,
		.has_arg = required_argument,
		.arg_desc = "<cluster>",
		.desc = "Point FAT entry beyond volume cluster heap range",
		.apply = fault_fat_out_of_bounds,
	},
	{
		.opt_name = "fat-mirror-diverge",
		.val = OPT_FAT_MIRROR_DIVERGE,
		.has_arg = optional_argument,
		.arg_desc = "[cluster]",
		.desc = "Mutate secondary FAT to diverge from active FAT",
		.apply = fault_fat_mirror_diverge,
	},
	{
		.opt_name = "bitmap-orphan",
		.val = OPT_BITMAP_ORPHAN,
		.has_arg = required_argument,
		.arg_desc = "<cluster>",
		.desc = "Mark unreferenced cluster allocated in bitmap",
		.apply = fault_bitmap_orphan,
	},
	{
		.opt_name = "bitmap-false-free",
		.val = OPT_BITMAP_FALSE_FREE,
		.has_arg = required_argument,
		.arg_desc = "<cluster>",
		.desc = "Clear bitmap allocation bit for an in-use cluster",
		.apply = fault_bitmap_false_free,
	},
	{
		.opt_name = "bitmap-truncate",
		.val = OPT_BITMAP_TRUNCATE,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Truncate allocation bitmap length in directory entry",
		.apply = fault_bitmap_truncate,
	},
	{
		.opt_name = "bitmap-mirror-diverge",
		.val = OPT_BITMAP_MIRROR_DIVERGE,
		.has_arg = optional_argument,
		.arg_desc = "[cluster]",
		.desc = "Mutate secondary Allocation Bitmap to diverge in "
		    "dual-FAT",
		.apply = fault_bitmap_mirror_diverge,
	},
	{
		.opt_name = "bitmap-flags-reserved",
		.val = OPT_BITMAP_FLAGS_RESERVED,
		.has_arg = optional_argument,
		.arg_desc = "[flags]",
		.desc = "Set invalid reserved bits in Allocation Bitmap flags",
		.apply = fault_bitmap_flags_reserved,
	},
	{
		.opt_name = "dentry-checksum",
		.val = OPT_DENTRY_CHECKSUM,
		.has_arg = required_argument,
		.arg_desc = "<target>",
		.desc = "Corrupt 16-bit SetChecksum of directory entry set",
		.apply = fault_dentry_checksum,
	},
	{
		.opt_name = "stream-vdl-exceeds-dl",
		.val = OPT_STREAM_VDL_EXCEEDS_DL,
		.has_arg = required_argument,
		.arg_desc = "<target>",
		.desc = "Set ValidDataLength > DataLength in stream extension",
		.apply = fault_stream_vdl_exceeds_dl,
	},
	{
		.opt_name = "stream-nofatchain-fragment",
		.val = OPT_STREAM_NOFATCHAIN_FRAGMENT,
		.has_arg = required_argument,
		.arg_desc = "<target>",
		.desc = "Set NoFatChain flag on fragmented cluster chain",
		.apply = fault_stream_nofatchain_fragment,
	},
	{
		.opt_name = "dentry-orphaned-secondary",
		.val = OPT_DENTRY_ORPHANED_SECONDARY,
		.has_arg = optional_argument,
		.arg_desc = "[offset]",
		.desc = "Create secondary dentry without primary entry",
		.apply = fault_dentry_orphaned_secondary,
	},
	{
		.opt_name = "dentry-root-in-subdir",
		.val = OPT_DENTRY_ROOT_IN_SUBDIR,
		.has_arg = required_argument,
		.arg_desc = "<target>",
		.desc = "Create invalid directory pointer back to root",
		.apply = fault_dentry_root_in_subdir,
	},
	{
		.opt_name = "dentry-secondary-count",
		.val = OPT_DENTRY_SECONDARY_COUNT,
		.has_arg = required_argument,
		.arg_desc = "<target> [count]",
		.desc = "Corrupt SecondaryCount in File directory entry",
		.apply = fault_dentry_secondary_count,
	},
	{
		.opt_name = "dentry-name-hash",
		.val = OPT_DENTRY_NAME_HASH,
		.has_arg = required_argument,
		.arg_desc = "<target> [hash]",
		.desc = "Corrupt NameHash in Stream Extension entry",
		.apply = fault_dentry_name_hash,
	},
	{
		.opt_name = "dentry-invalid-name-chars",
		.val = OPT_DENTRY_INVALID_NAME_CHARS,
		.has_arg = required_argument,
		.arg_desc = "<target> [char]",
		.desc = "Inject forbidden characters into File Name entries",
		.apply = fault_dentry_invalid_name_chars,
	},
	{
		.opt_name = "dentry-size-mismatch",
		.val = OPT_DENTRY_SIZE_MISMATCH,
		.has_arg = required_argument,
		.arg_desc = "<target> [bytes]",
		.desc = "Set DataLength/ValidDataLength mismatching FAT "
		    "chain size",
		.apply = fault_dentry_size_mismatch,
	},
	{
		.opt_name = "upcase-checksum-mismatch",
		.val = OPT_UPCASE_CHECKSUM_MISMATCH,
		.has_arg = optional_argument,
		.arg_desc = "[csum]",
		.desc = "Corrupt TableChecksum in Up-case directory entry",
		.apply = fault_upcase_checksum_mismatch,
	},
	{
		.opt_name = "upcase-truncate",
		.val = OPT_UPCASE_TRUNCATE,
		.has_arg = optional_argument,
		.arg_desc = "[bytes|chain]",
		.desc = "Truncate Up-case Table DataLength or cluster chain",
		.apply = fault_upcase_truncate,
	},
	{
		.opt_name = "label-duplicate",
		.val = OPT_LABEL_DUPLICATE,
		.has_arg = optional_argument,
		.arg_desc = "[name]",
		.desc = "Inject duplicate Volume Label directory entry in "
		    "root",
		.apply = fault_label_duplicate,
	},
	{
		.opt_name = "label-invalid-chars",
		.val = OPT_LABEL_INVALID_CHARS,
		.has_arg = optional_argument,
		.arg_desc = "[char]",
		.desc = "Inject forbidden characters into Volume Label entry",
		.apply = fault_label_invalid_chars,
	},
	{
		.opt_name = "label-length",
		.val = OPT_LABEL_LENGTH,
		.has_arg = optional_argument,
		.arg_desc = "[count]",
		.desc = "Set CharacterCount > 11 in Volume Label entry",
		.apply = fault_label_length,
	},
	{
		.opt_name = "guid-duplicate",
		.val = OPT_GUID_DUPLICATE,
		.has_arg = optional_argument,
		.arg_desc = "[guid]",
		.desc = "Inject duplicate Volume GUID directory entry in "
		    "root",
		.apply = fault_guid_duplicate,
	},
	{
		.opt_name = "guid-invalid",
		.val = OPT_GUID_INVALID,
		.has_arg = optional_argument,
		.arg_desc = "[field]",
		.desc = "Set non-zero SecondaryCount or Flags in Volume GUID",
		.apply = fault_guid_invalid,
	},
	{
		.opt_name = "dump-all",
		.val = OPT_DUMP_ALL,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Comprehensive audit report of all volume structures",
		.is_utility = true,
		.apply = util_dump_all,
	},
	{
		.opt_name = "dump-bitmap",
		.val = OPT_DUMP_BITMAP,
		.has_arg = optional_argument,
		.arg_desc = "[range]",
		.desc = "Dump Allocation Bitmap allocation status and runs",
		.is_utility = true,
		.apply = util_dump_bitmap,
	},
	{
		.opt_name = "dump-boot",
		.val = OPT_DUMP_BOOT,
		.has_arg = optional_argument,
		.arg_desc = "[main|backup]",
		.desc = "Dump Boot Sector parameters and verify checksums",
		.is_utility = true,
		.apply = util_dump_boot,
	},
	{
		.opt_name = "dump-fat",
		.val = OPT_DUMP_FAT,
		.has_arg = optional_argument,
		.arg_desc = "[range|cn]",
		.desc = "Dump FAT entries, cluster chains, and summary",
		.is_utility = true,
		.apply = util_dump_fat,
	},
	{
		.opt_name = "dump-dentries",
		.val = OPT_DUMP_DENTRIES,
		.has_arg = optional_argument,
		.arg_desc = "[path|cn]",
		.desc = "Dump directory entries, entry sets, and attributes",
		.is_utility = true,
		.apply = util_dump_dentries,
	},
	{
		.opt_name = "verify",
		.val = OPT_VERIFY,
		.has_arg = no_argument,
		.arg_desc = NULL,
		.desc = "Verify volume consistency and defect summary",
		.is_utility = true,
		.apply = util_verify,
	},
};

#define NFAULTS nitems(fault_handlers)

/*
 * Print formatted usage entries for either utility or fault injection options.
 */
static void
print_option_group(FILE *fp, bool utility)
{
	for (size_t i = 0; i < NFAULTS; i++) {
		char optbuf[64];

		if (fault_handlers[i].is_utility != utility)
			continue;
		if (fault_handlers[i].arg_desc != NULL)
			snprintf(optbuf, sizeof(optbuf), "--%s %s",
			    fault_handlers[i].opt_name,
			    fault_handlers[i].arg_desc);
		else
			snprintf(optbuf, sizeof(optbuf), "--%s",
			    fault_handlers[i].opt_name);
		fprintf(fp, "  %-45s %s\n", optbuf, fault_handlers[i].desc);
	}
}

/*
 * Print program usage and list available fault injection and utility options.
 */
static void
usage(int eval)
{
	FILE *fp;

	fp = (eval == 0) ? stdout : stderr;
	fprintf(fp,
	    "usage: exfat_faultgen [options] <image>\n"
	    "\n"
	    "General options:\n"
	    "  -h, --help                                    "
	    "Show this help message\n"
	    "  -j, --json                                    "
	    "Emit output in JSON format\n"
	    "  -n, --dry-run                                 "
	    "Check only; do not write mutations\n"
	    "  -v, --verbose                                 "
	    "Verbose diagnostics\n"
	    "\n"
	    "Inspection and utility options:\n");

	print_option_group(fp, true);

	fprintf(fp, "\nFault injection options (select exactly one):\n");
	print_option_group(fp, false);
	exit(eval);
}

/*
 * Parse command line options and dispatch selected fault generator.
 */
int
main(int argc, char *argv[])
{
	struct option longopts[NFAULTS + 5];
	struct faultgen_ctx ctx;
	const struct fault_handler *selected_fault;
	const char *selected_arg;
	char *allocated_arg;
	int ch, error;
	bool found;

	selected_fault = NULL;
	selected_arg = NULL;
	allocated_arg = NULL;
	memset(&ctx, 0, sizeof(ctx));
	ctx.fd = -1;

	/* Populate long options from fault_handlers table. */
	for (size_t i = 0; i < NFAULTS; i++) {
		longopts[i].name = fault_handlers[i].opt_name;
		longopts[i].has_arg = fault_handlers[i].has_arg;
		longopts[i].flag = NULL;
		longopts[i].val = fault_handlers[i].val;
	}
	longopts[NFAULTS] = (struct option){ "help", no_argument, NULL, 'h' };
	longopts[NFAULTS + 1] =
	    (struct option){ "dry-run", no_argument, NULL, 'n' };
	longopts[NFAULTS + 2] =
	    (struct option){ "verbose", no_argument, NULL, 'v' };
	longopts[NFAULTS + 3] =
	    (struct option){ "json", no_argument, NULL, 'j' };
	longopts[NFAULTS + 4] = (struct option){ NULL, 0, NULL, 0 };

	while ((ch = getopt_long(argc, argv, "hjnv", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			usage(0);
			break;
		case 'j':
			ctx.json = true;
			break;
		case 'n':
			ctx.dry_run = true;
			break;
		case 'v':
			ctx.verbose = true;
			break;
		case '?':
			usage(1);
			break;
		default:
			/* Match fault injection and utility options. */
			found = false;
			for (size_t i = 0; i < NFAULTS; i++) {
				if (fault_handlers[i].val != ch)
					continue;
				if (selected_fault != NULL)
					errx(1, "multiple operations "
					    "specified; faults and utilities "
					    "must be run independently");
				selected_fault = &fault_handlers[i];
				selected_arg = optarg;
				found = true;
				break;
			}
			if (!found)
				usage(1);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (selected_fault == NULL && ctx.json) {
		for (size_t i = 0; i < NFAULTS; i++) {
			if (fault_handlers[i].val == OPT_VERIFY) {
				selected_fault = &fault_handlers[i];
				break;
			}
		}
	}

	if (selected_fault == NULL) {
		warnx("no fault injection or utility option specified");
		usage(1);
	}
	if (argc == 2) {
		if (selected_fault->has_arg == optional_argument &&
		    selected_arg == NULL) {
			selected_arg = argv[0];
			argv++;
			argc--;
		} else if (selected_arg != NULL &&
		    (selected_fault->val == OPT_DENTRY_SECONDARY_COUNT ||
		    selected_fault->val == OPT_DENTRY_NAME_HASH ||
		    selected_fault->val == OPT_DENTRY_INVALID_NAME_CHARS ||
		    selected_fault->val == OPT_DENTRY_SIZE_MISMATCH)) {
			if (asprintf(&allocated_arg, "%s,%s", selected_arg,
			    argv[0]) == -1)
				err(1, "asprintf");
			selected_arg = allocated_arg;
			argv++;
			argc--;
		}
	}
	if (argc < 1) {
		free(allocated_arg);
		warnx("missing image file operand");
		usage(1);
	}
	if (argc > 1) {
		free(allocated_arg);
		warnx("extra operand '%s'", argv[1]);
		usage(1);
	}

	ctx.image_path = argv[0];
	if (selected_fault->is_utility)
		ctx.dry_run = true;

	if (ctx.verbose && !ctx.json) {
		printf("Selected operation: %s\n", selected_fault->opt_name);
		if (selected_arg != NULL)
			printf("Operation argument: %s\n", selected_arg);
		printf("Target image:       %s\n", ctx.image_path);
	}

	error = selected_fault->apply(&ctx, selected_arg);
	free(allocated_arg);
	if (error != 0) {
		close_image(&ctx);
		if (selected_fault->val == OPT_VERIFY && error == EBADMSG)
			exit(1);
		errx(1, "%s '%s' failed: %s",
		    selected_fault->is_utility ? "utility" : "fault",
		    selected_fault->opt_name, strerror(error));
	}

	close_image(&ctx);
	return (0);
}
