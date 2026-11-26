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

#ifndef _FAULTGEN_SUBR_H_
#define _FAULTGEN_SUBR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct faultgen_ctx;

int	ensure_image_open(struct faultgen_ctx *ctx);
void	format_bytes(uint64_t bytes, char *buf, size_t buflen);
void	format_guid(const uint8_t *guid, char *buf, size_t size);
bool	is_all_zero(const void *buf, size_t len);
int	parse_cluster_range(const char *arg, uint32_t cluster_count,
	    uint32_t *start_cn, uint32_t *end_cn, bool *is_single);
int	parse_guid(const char *str, uint8_t *guid);
void	parse_target_and_param(const char *arg, char *target_buf,
	    size_t target_sz, const char **param_out);
int	parse_u32_str(const char *str, char **endp_out, uint32_t *val_out);
int	parse_u64_str(const char *str, char **endp_out, uint64_t *val_out);
void	print_divider(char ch);
void	print_json_string(const char *str, size_t max_len);
void	utf16_to_utf8(const uint16_t *src, size_t nchars, char *dst,
	    size_t dstlen);

#endif /* _FAULTGEN_SUBR_H_ */
