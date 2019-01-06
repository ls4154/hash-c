#include <stdlib.h>
#include <string.h>

#include "sha1.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void sha1_init(struct sha1_ctx *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;

	ctx->len = 0;
}

static void _sha1_iterate(struct sha1_ctx *ctx, byte_t *chunk)
{
	word_t w[80];

	for (int i = 0; i < 16; ++i) {
		w[i] = 0;
		for (int j = 0; j < 4; ++j)
			w[i] |= (word_t)*(chunk + 4 * i + j) << 8 * (3 - j);
	}

	for (int i = 16; i < 80; ++i)
		w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	word_t a = ctx->h[0];
	word_t b = ctx->h[1];
	word_t c = ctx->h[2];
	word_t d = ctx->h[3];
	word_t e = ctx->h[4];

	for (int i = 0; i < 80; ++i) {
		word_t tmp;
		word_t k;

		switch (i / 20) {
		case 0:
			tmp = (b & c) | ((~b) & d);
			k = 0x5a827999;
			break;
		case 1:
			tmp = b ^ c ^ d;
			k = 0x6ed9eba1;
			break;
		case 2:
			tmp = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdc;
			break;
		default :
			tmp = b ^ c ^ d;
			k = 0xca62c1d6;
		}
		tmp += ROL(a, 5) + e + k + w[i];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

void sha1_update(struct sha1_ctx *ctx, byte_t *chunk)
{
	_sha1_iterate(ctx, chunk);
	ctx->len += 64;
}

void sha1_update_last(struct sha1_ctx *ctx, byte_t *chunk, len_t len)
{
	ctx->len += len;
	len_t bit_len = ctx->len * 8;

	byte_t padding[64];
	memset(padding, 0, sizeof(padding));

	memcpy(padding, chunk, len);
	*(padding + len) = 0x80;

	if (len >= 56) {
		_sha1_iterate(ctx, padding);
		memset(padding, 0, sizeof(padding));
	}

	byte_t *ptr = padding + 56;
	for (int i = 7; i >= 0; --i) {
		*ptr = (bit_len >> 8 * i) & 0xFF;
		++ptr;
	}
	_sha1_iterate(ctx, padding);
}

void sha1_offline(struct sha1_ctx *ctx, byte_t *msg, len_t len)
{
	sha1_init(ctx);

	while (len >= 64) {
		sha1_update(ctx, msg);

		msg += 64;
		len -= 64;
	}

	sha1_update_last(ctx, msg, len);
}
