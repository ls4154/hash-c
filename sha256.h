#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

typedef uint8_t byte_t;
typedef uint32_t word_t;
typedef uint64_t len_t;

#define WORD_CNT 8

struct sha256_ctx {
	word_t h[WORD_CNT];
	len_t len;
};

void sha256_init(struct sha256_ctx *ctx);

void sha256_update(struct sha256_ctx *ctx, byte_t *chunk);

void sha256_update_last(struct sha256_ctx *ctx, byte_t *chunk, len_t len);

void sha256_offline(struct sha256_ctx *ctx, byte_t *msg, len_t len);

#endif
