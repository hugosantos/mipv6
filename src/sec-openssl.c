/*
 * MIPv6, an IPv6 mobility framework
 *
 * Copyright (C) 2006, 2007 Hugo Santos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Hugo Santos <hugo@fivebits.net>
 */

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <mblty/base-support.h>

#include "sec-openssl.h"

void
hmac_sha1_init_with_key(struct hmac_sha1_ctx *ctx, uint8_t *key, int keylen)
{
	HMAC_CTX_init(&ctx->hmac);
	HMAC_Init_ex(&ctx->hmac, key, keylen, EVP_sha1(), NULL);
}

void
hmac_sha1_add_data(struct hmac_sha1_ctx *ctx, uint8_t *buf, int buflen)
{
	HMAC_Update(&ctx->hmac, buf, buflen);
}

void
hmac_sha1_obtain(struct hmac_sha1_ctx *ctx, uint8_t *buf)
{
	HMAC_Final(&ctx->hmac, buf, NULL);
	HMAC_CTX_cleanup(&ctx->hmac);
}

void
sha1_init(struct sha1_ctx *ctx)
{
	SHA1_Init(&ctx->sha);
}

void
sha1_add_data(struct sha1_ctx *ctx, uint8_t *buf, int buflen)
{
	SHA1_Update(&ctx->sha, buf, buflen);
}

void
sha1_obtain(struct sha1_ctx *ctx, uint8_t *buf)
{
	SHA1_Final(buf, &ctx->sha);
}

uint8_t *
random_pseudo_bytes(uint8_t *buf, int buflen)
{
	RAND_pseudo_bytes(buf, buflen);
	return buf;
}

void
proto_sec_openssl_init()
{
	uint8_t x;

	SSL_library_init();

	if (RAND_pseudo_bytes(&x, sizeof(x)) < 0)
		perform_shutdown("RAND_pseudo_bytes does not work");
}

