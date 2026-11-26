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

#include <ctype.h>
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

/*
 * Parse an unsigned 32-bit integer from str, rejecting empty strings,
 * leading minus signs, and values exceeding UINT32_MAX.
 */
int
parse_u32_str(const char *str, char **endp_out, uint32_t *val_out)
{
	char *endp;
	uint64_t val;

	if (str == NULL || val_out == NULL)
		return (EINVAL);

	if (parse_u64_str(str, &endp, &val) != 0 || val > UINT32_MAX)
		return (EINVAL);

	if (endp_out != NULL)
		*endp_out = endp;
	else if (*endp != '\0')
		return (EINVAL);

	*val_out = (uint32_t)val;
	return (0);
}

/*
 * Parse an unsigned 64-bit integer from str, rejecting empty strings,
 * leading minus signs, and values exceeding UINT64_MAX.
 */
int
parse_u64_str(const char *str, char **endp_out, uint64_t *val_out)
{
	char *endp;
	unsigned long long val;
	const char *p;

	if (str == NULL || val_out == NULL)
		return (EINVAL);

	p = str;
	while (isspace((unsigned char)*p))
		p++;
	if (*p == '\0' || *p == '-')
		return (EINVAL);

	errno = 0;
	val = strtoull(p, &endp, 0);
	if (endp == p || errno == ERANGE)
		return (EINVAL);

	if (endp_out != NULL)
		*endp_out = endp;
	else if (*endp != '\0')
		return (EINVAL);

	*val_out = (uint64_t)val;
	return (0);
}

/*
 * Ensure target image is opened and volume geometry is loaded.
 */
int
ensure_image_open(struct faultgen_ctx *ctx)
{
	if (ctx == NULL)
		return (EINVAL);
	if (ctx->fd >= 0)
		return (0);

	return (open_image(ctx, ctx->image_path));
}

/*
 * Check whether a memory buffer contains exclusively zero bytes.
 */
bool
is_all_zero(const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;

	if (buf == NULL)
		return (true);

	for (size_t i = 0; i < len; i++) {
		if (p[i] != 0)
			return (false);
	}
	return (true);
}

/*
 * Format a byte count into a human-readable size string.
 */
void
format_bytes(uint64_t bytes, char *buf, size_t buflen)
{
	if (bytes >= (1ULL << 30))
		snprintf(buf, buflen, "%.2f GiB",
		    (double)bytes / (1ULL << 30));
	else if (bytes >= (1ULL << 20))
		snprintf(buf, buflen, "%.2f MiB",
		    (double)bytes / (1ULL << 20));
	else if (bytes >= (1ULL << 10))
		snprintf(buf, buflen, "%.2f KiB",
		    (double)bytes / (1ULL << 10));
	else
		snprintf(buf, buflen, "%" PRIu64 " bytes", bytes);
}

/*
 * Format 128-bit GUID into standard hyphenated representation.
 */
void
format_guid(const uint8_t *guid, char *buf, size_t size)
{
	uint32_t d1;
	uint16_t d2, d3;

	if (guid == NULL || buf == NULL || size == 0)
		return;

	d1 = (uint32_t)guid[0] | ((uint32_t)guid[1] << 8) |
	    ((uint32_t)guid[2] << 16) | ((uint32_t)guid[3] << 24);
	d2 = (uint16_t)guid[4] | ((uint16_t)guid[5] << 8);
	d3 = (uint16_t)guid[6] | ((uint16_t)guid[7] << 8);
	snprintf(buf, size,
	    "{%08" PRIX32 "-%04" PRIX16 "-%04" PRIX16 "-%02" PRIX8 "%02" PRIX8
	    "-%02" PRIX8 "%02" PRIX8 "%02" PRIX8 "%02" PRIX8 "%02" PRIX8
	    "%02" PRIX8 "}",
	    d1, d2, d3, guid[8], guid[9], guid[10], guid[11],
	    guid[12], guid[13], guid[14], guid[15]);
}

/*
 * Parse a GUID string in standard format {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 * or without curly braces.
 */
int
parse_guid(const char *str, uint8_t *guid)
{
	unsigned int d1, d2, d3;
	unsigned int b[8];
	int n, pos;
	bool had_brace;

	if (str == NULL || guid == NULL)
		return (EINVAL);

	had_brace = (*str == '{');
	if (had_brace)
		str++;

	pos = 0;
	n = sscanf(str,
	    "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x%n",
	    &d1, &d2, &d3,
	    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &pos);
	if (n != 11 || pos != 36)
		return (EINVAL);

	if (had_brace) {
		if (str[pos] != '}' || str[pos + 1] != '\0')
			return (EINVAL);
	} else if (str[pos] != '\0')
		return (EINVAL);

	guid[0] = (uint8_t)(d1 & 0xFF);
	guid[1] = (uint8_t)((d1 >> 8) & 0xFF);
	guid[2] = (uint8_t)((d1 >> 16) & 0xFF);
	guid[3] = (uint8_t)((d1 >> 24) & 0xFF);
	guid[4] = (uint8_t)(d2 & 0xFF);
	guid[5] = (uint8_t)((d2 >> 8) & 0xFF);
	guid[6] = (uint8_t)(d3 & 0xFF);
	guid[7] = (uint8_t)((d3 >> 8) & 0xFF);
	for (int i = 0; i < 8; i++)
		guid[8 + i] = (uint8_t)b[i];

	return (0);
}

/*
 * Parse target identifier and optional secondary argument separated by
 * a comma or space (e.g. "<target> [extra_arg]").
 */
void
parse_target_and_param(const char *arg, char *target_buf, size_t target_sz,
    const char **param_out)
{
	const char *sep;
	size_t len;

	if (param_out != NULL)
		*param_out = NULL;
	if (arg == NULL || *arg == '\0') {
		if (target_sz > 0)
			target_buf[0] = '\0';
		return;
	}

	sep = strchr(arg, ',');
	if (sep == NULL)
		sep = strchr(arg, ' ');

	if (sep != NULL) {
		len = (size_t)(sep - arg);
		if (len >= target_sz)
			len = target_sz - 1;
		memcpy(target_buf, arg, len);
		target_buf[len] = '\0';
		if (param_out != NULL) {
			const char *p = sep + 1;

			while (*p == ' ')
				p++;
			if (*p != '\0')
				*param_out = p;
		}
	} else
		strlcpy(target_buf, arg, target_sz);
}

/*
 * Parse cluster range or single cluster argument (Spec §4.1, §7.1).
 */
int
parse_cluster_range(const char *arg, uint32_t cluster_count,
    uint32_t *start_cn, uint32_t *end_cn, bool *is_single)
{
	char *endp;
	uint32_t max_cn, v1, v2;

	max_cn = EXFAT_FIRST_CLUSTER + cluster_count - 1;

	if (arg == NULL || *arg == '\0') {
		*start_cn = EXFAT_FIRST_CLUSTER;
		*end_cn = max_cn;
		*is_single = false;
		return (0);
	}

	if (parse_u32_str(arg, &endp, &v1) != 0 ||
	    v1 < EXFAT_FIRST_CLUSTER || v1 > max_cn)
		return (EINVAL);

	if (*endp == '\0') {
		*start_cn = v1;
		*end_cn = v1;
		*is_single = true;
		return (0);
	}

	if (*endp == ',' || *endp == '-') {
		if (parse_u32_str(endp + 1, NULL, &v2) != 0 ||
		    v2 < v1 || v2 > max_cn)
			return (EINVAL);
		*start_cn = v1;
		*end_cn = v2;
		*is_single = (v1 == v2);
		return (0);
	}

	return (EINVAL);
}

/*
 * Print a horizontal divider line of specified character.
 */
void
print_divider(char ch)
{
	for (int i = 0; i < 78; i++)
		putchar(ch);
	putchar('\n');
}

/*
 * Print a JSON-escaped double-quoted string of up to max_len bytes.
 */
void
print_json_string(const char *str, size_t max_len)
{
	putchar('"');
	if (str != NULL) {
		for (size_t i = 0; i < max_len && str[i] != '\0'; i++) {
			unsigned char c = (unsigned char)str[i];

			switch (c) {
			case '"':
				fputs("\\\"", stdout);
				break;
			case '\\':
				fputs("\\\\", stdout);
				break;
			case '\b':
				fputs("\\b", stdout);
				break;
			case '\f':
				fputs("\\f", stdout);
				break;
			case '\n':
				fputs("\\n", stdout);
				break;
			case '\r':
				fputs("\\r", stdout);
				break;
			case '\t':
				fputs("\\t", stdout);
				break;
			default:
				if (c < 0x20)
					printf("\\u%04x", c);
				else
					putchar(c);
				break;
			}
		}
	}
	putchar('"');
}

/*
 * Convert a UTF-16 string of length nchars to a null-terminated UTF-8 string
 * of size dstlen bytes.  Correctly decodes surrogate pairs into 4-byte UTF-8
 * sequences, and emits the Unicode replacement character (U+FFFD) for unpaired
 * surrogates.  Guarantees null-termination when dstlen > 0.
 */
void
utf16_to_utf8(const uint16_t *src, size_t nchars, char *dst, size_t dstlen)
{
	size_t di = 0;

	if (dstlen == 0)
		return;

	for (size_t si = 0; si < nchars; si++) {
		uint16_t c = src[si];

		if (c == 0)
			break;
		if (c < 0x80) {
			if (di + 1 >= dstlen)
				break;
			dst[di++] = (char)c;
		} else if (c < 0x800) {
			if (di + 2 >= dstlen)
				break;
			dst[di++] = (char)(0xC0 | (c >> 6));
			dst[di++] = (char)(0x80 | (c & 0x3F));
		} else if (c >= 0xD800 && c <= 0xDFFF) {
			if (c <= 0xDBFF && si + 1 < nchars) {
				uint16_t c2 = src[si + 1];

				if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
					uint32_t cp;

					if (di + 4 >= dstlen)
						break;
					cp = 0x10000 +
					    (((uint32_t)(c - 0xD800) << 10) |
					    (c2 - 0xDC00));
					dst[di++] = (char)(0xF0 | (cp >> 18));
					dst[di++] = (char)(0x80 |
					    ((cp >> 12) & 0x3F));
					dst[di++] = (char)(0x80 |
					    ((cp >> 6) & 0x3F));
					dst[di++] = (char)(0x80 | (cp & 0x3F));
					si++;
					continue;
				}
			}
			/* Unpaired surrogate: emit U+FFFD replacement char */
			if (di + 3 >= dstlen)
				break;
			dst[di++] = (char)0xEF;
			dst[di++] = (char)0xBF;
			dst[di++] = (char)0xBD;
		} else {
			if (di + 3 >= dstlen)
				break;
			dst[di++] = (char)(0xE0 | (c >> 12));
			dst[di++] = (char)(0x80 | ((c >> 6) & 0x3F));
			dst[di++] = (char)(0x80 | (c & 0x3F));
		}
	}
	dst[di] = '\0';
}
