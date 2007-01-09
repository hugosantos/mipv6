#ifndef _PROTO_SEC_OPENSSL_H_
#define _PROTO_SEC_OPENSSL_H_

#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

struct hmac_sha1_ctx {
	HMAC_CTX hmac;
};

struct sha1_ctx {
	SHA_CTX sha;
};

#define SHA1_LENGTH	(160 / 8)

void hmac_sha1_init_with_key(struct hmac_sha1_ctx *, uint8_t *, int);
void hmac_sha1_add_data(struct hmac_sha1_ctx *, uint8_t *, int);
void hmac_sha1_obtain(struct hmac_sha1_ctx *, uint8_t *);

void sha1_init(struct sha1_ctx *);
void sha1_add_data(struct sha1_ctx *, uint8_t *, int);
void sha1_obtain(struct sha1_ctx *, uint8_t *);

uint8_t *random_pseudo_bytes(uint8_t *, int);

void proto_sec_openssl_init();

#endif
