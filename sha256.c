#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const word_t k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

void sha256_init(struct sha256_ctx *ctx)
{
	ctx->h[0] = 0x6a09e667u;
	ctx->h[1] = 0xbb67ae85u;
	ctx->h[2] = 0x3c6ef372u;
	ctx->h[3] = 0xa54ff53au;
	ctx->h[4] = 0x510e527fu;
	ctx->h[5] = 0x9b05688cu;
	ctx->h[6] = 0x1f83d9abu;
	ctx->h[7] = 0x5be0cd19u;

	ctx->len = 0;
}

static void _sha256_iterate(struct sha256_ctx *ctx, byte_t *chunk)
{
	word_t w[64];

	for (int i = 0; i < 16; ++i) {
		w[i] = 0;
		for (int j = 0; j < 4; ++j)
			w[i] |= (word_t)*(chunk + 4 * i + j) << 8 * (3 - j);
	}

	for (int i = 16; i < 64; ++i) {
		word_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ ROR(w[i - 15], 3);
		word_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ ROR(w[i - 2], 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	word_t a = ctx->h[0];
	word_t b = ctx->h[1];
	word_t c = ctx->h[2];
	word_t d = ctx->h[3];
	word_t e = ctx->h[4];
	word_t f = ctx->h[5];
	word_t g = ctx->h[6];
	word_t h = ctx->h[7];

	for (int i = 0; i < 64; ++i) {
		word_t s1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
		word_t ch = (e & f) ^ ((~e) & g);
		word_t tmp1 = h + s1 + ch + k[i] + w[i];
		word_t s0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
		word_t maj = (a & b) ^ (a & c) ^ (b & c);
		word_t tmp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + tmp1;
		d = c;
		c = b;
		b = a;
		a = tmp1 + tmp2;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

void sha256_update(struct sha256_ctx *ctx, byte_t *chunk)
{
	_sha256_iterate(ctx, chunk);
	ctx->len += 64;
}

void sha256_update_last(struct sha256_ctx *ctx, byte_t *chunk, len_t len)
{
	ctx->len += len;
	len_t bit_len = ctx->len * 8;

	byte_t padding[64];
	memset(padding, 0, sizeof(padding));

	memcpy(padding, chunk, len);
	*(padding + len) = 0x80;

	if (len >= 56) {
		_sha256_iterate(ctx, padding);
		memset(padding, 0, sizeof(padding));
	}

	byte_t *ptr = padding + 56;
	for (int i = 7; i >= 0; --i) {
		*ptr = (bit_len >> 8 * i) & 0xFF;
		++ptr;
	}
	_sha256_iterate(ctx, padding);
}

void sha256_offline(struct sha256_ctx *ctx, byte_t *msg, len_t len)
{
	sha256_init(ctx);

	while (len >= 64) {
		sha256_update(ctx, msg);

		msg += 64;
		len -= 64;
	}

	sha256_update_last(ctx, msg, len);
}
