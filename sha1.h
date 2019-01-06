#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

typedef uint8_t byte_t;
typedef uint32_t word_t;
typedef uint64_t len_t;

#define WORD_CNT 5

struct sha1_ctx {
	word_t h[WORD_CNT];
	len_t len;
};

void sha1_init(struct sha1_ctx *ctx);

void sha1_update(struct sha1_ctx *ctx, byte_t *chunk);

void sha1_update_last(struct sha1_ctx *ctx, byte_t *chunk, len_t len);

void sha1_offline(struct sha1_ctx *ctx, byte_t *msg, len_t len);

#endif
