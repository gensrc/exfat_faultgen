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

#ifndef _FAULTGEN_IO_H_
#define _FAULTGEN_IO_H_

#include <stdbool.h>
#include <stdint.h>

struct exfat_boot_sector;
struct faultgen_ctx;

int	open_image(struct faultgen_ctx *ctx, const char *path);
void	close_image(struct faultgen_ctx *ctx);
int	sync_image(struct faultgen_ctx *ctx);
int	read_sector(struct faultgen_ctx *ctx, uint64_t sector, void *buf);
int	write_sector(struct faultgen_ctx *ctx, uint64_t sector,
	    const void *buf);
int	read_cluster(struct faultgen_ctx *ctx, uint32_t cn, void *buf);
int	write_cluster(struct faultgen_ctx *ctx, uint32_t cn,
	    const void *buf);
int	fat_get(struct faultgen_ctx *ctx, uint32_t cn, uint32_t *val);
int	fat_set_all(struct faultgen_ctx *ctx, uint32_t cn, uint32_t val);
int	fat_get_entry(struct faultgen_ctx *ctx, uint8_t fat_idx,
	    uint32_t cn, uint32_t *val);
int	fat_set_entry(struct faultgen_ctx *ctx, uint8_t fat_idx,
	    uint32_t cn, uint32_t val);

#endif /* _FAULTGEN_IO_H_ */
