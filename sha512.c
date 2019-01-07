#include <stdlib.h>
#include <string.h>

#include "sha512.h"

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))

static const word_t k[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

void sha512_init(struct sha512_ctx *ctx)
{
	ctx->h[0] = 0x6a09e667f3bcc908ull;
	ctx->h[1] = 0xbb67ae8584caa73bull;
	ctx->h[2] = 0x3c6ef372fe94f82bull;
	ctx->h[3] = 0xa54ff53a5f1d36f1ull;
	ctx->h[4] = 0x510e527fade682d1ull;
	ctx->h[5] = 0x9b05688c2b3e6c1full;
	ctx->h[6] = 0x1f83d9abfb41bd6bull;
	ctx->h[7] = 0x5be0cd19137e2179ull;

	ctx->len = 0;
}

static void _sha512_iterate(struct sha512_ctx *ctx, byte_t *chunk)
{
	word_t w[80];

	for (int i = 0; i < 16; ++i) {
		w[i] = 0;
		for (int j = 0; j < 8; ++j)
			w[i] |= (word_t)*(chunk + 8 * i + j) << 8 * (7 - j);
	}

	for (int i = 16; i < 80; ++i) {
		word_t s0 = ROR(w[i - 15], 1) ^ ROR(w[i - 15], 8) ^ SHR(w[i - 15], 7);
		word_t s1 = ROR(w[i - 2], 19) ^ ROR(w[i - 2], 61) ^ SHR(w[i - 2], 6);
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

	for (int i = 0; i < 80; ++i) {
		word_t s1 = ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41);
		word_t ch = (e & f) ^ ((~e) & g);
		word_t tmp1 = h + s1 + ch + k[i] + w[i];
		word_t s0 = ROR(a, 28) ^ ROR(a, 34) ^ ROR(a, 39);
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

void sha512_update(struct sha512_ctx *ctx, byte_t *chunk)
{
	_sha512_iterate(ctx, chunk);
	ctx->len += 128;
}

void sha512_update_last(struct sha512_ctx *ctx, byte_t *chunk, len_t len)
{
	ctx->len += len;
	len_t bit_len = ctx->len * 8;

	byte_t padding[128];
	memset(padding, 0, sizeof(padding));

	memcpy(padding, chunk, len);
	*(padding + len) = 0x80;

	if (len >= 112) {
		_sha512_iterate(ctx, padding);
		memset(padding, 0, sizeof(padding));
	}

	/* todo : length should be 128 bit */
	byte_t *ptr = padding + 112 + 8;
	for (int i = 7; i >= 0; --i) {
		*ptr = (bit_len >> 8 * i) & 0xFF;
		++ptr;
	}
	_sha512_iterate(ctx, padding);
}

void sha512_offline(struct sha512_ctx *ctx, byte_t *msg, len_t len)
{
	sha512_init(ctx);

	while (len >= 128) {
		sha512_update(ctx, msg);

		msg += 128;
		len -= 128;
	}

	sha512_update_last(ctx, msg, len);
}

