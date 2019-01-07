#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

typedef uint8_t byte_t;
typedef uint64_t word_t;
typedef uint64_t len_t;

#define WORD_CNT 8

struct sha512_ctx {
	word_t h[WORD_CNT];
	len_t len;
};

void sha512_init(struct sha512_ctx *ctx);

void sha512_update(struct sha512_ctx *ctx, byte_t *chunk);

void sha512_update_last(struct sha512_ctx *ctx, byte_t *chunk, len_t len);

void sha512_offline(struct sha512_ctx *ctx, byte_t *msg, len_t len);

#endif

