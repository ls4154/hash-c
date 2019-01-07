#ifndef SHA224_H
#define SHA224_H

#include <stdint.h>

typedef uint8_t byte_t;
typedef uint32_t word_t;
typedef uint64_t len_t;

#define WORD_CNT 8

struct sha224_ctx {
	word_t h[WORD_CNT];
	len_t len;
};

void sha224_init(struct sha224_ctx *ctx);

void sha224_update(struct sha224_ctx *ctx, byte_t *chunk);

void sha224_update_last(struct sha224_ctx *ctx, byte_t *chunk, len_t len);

void sha224_offline(struct sha224_ctx *ctx, byte_t *msg, len_t len);

#endif
