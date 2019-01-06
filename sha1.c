#include <stdlib.h>
#include <string.h>

#include "sha1.h"

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) ((x) ^ (y) ^ (z))
#define H(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void _sha1_iterate(byte_t *msg, word_t *h)
{
	word_t w[80];

	for (int i = 0; i < 16; ++i) {
		w[i] = 0;
		for (int j = 0; j < 4; ++j)
			w[i] |= (word_t)*(msg + 4 * i + j) << 8 * (3 - j);
	}

	for (int i = 16; i < 80; ++i)
		w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	word_t a = h[0];
	word_t b = h[1];
	word_t c = h[2];
	word_t d = h[3];
	word_t e = h[4];

	for (int i = 0; i < 80; ++i) {
		word_t tmp;
		word_t k;

		switch (i / 20) {
		case 0:
			tmp = F(b, c, d);
			k = 0x5a827999;
			break;
		case 1:
			tmp = G(b, c, d);
			k = 0x6ed9eba1;
			break;
		case 2:
			tmp = H(b, c, d);
			k = 0x8f1bbcdc;
			break;
		default :
			k = 0xca62c1d6;
			tmp = G(b, c, d);
		}
		tmp += ROL(a, 5) + e + k + w[i];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}

	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void sha1(byte_t *msg, len_t len, byte_t *result)
{
	len_t bit_len = len * 8;

	word_t h[5] = {
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
		0xc3d2e1f0
	};

	while (len >= 64) {
		_sha1_iterate(msg, h);

		msg += 64;
		len -= 64;
	}

	byte_t padding[64];
	memset(padding, 0, sizeof(padding));

	memcpy(padding, msg, len);
	*(padding + len) = 0x80;

	if (len >= 56) {
		_sha1_iterate(padding, h);
		memset(padding, 0, sizeof(padding));
	}

	byte_t *ptr = padding + 56;
	for (int i = 7; i >= 0; --i) {
		*ptr = (bit_len >> 8 * i) & 0xFF;
		++ptr;
	}
	_sha1_iterate(padding, h);

	if (result == NULL)
		result = malloc(20);

	for (int i = 0; i < 5; ++i) {
		for (int j = 3; j >= 0; --j) {
			*result = (h[i] >> 8 * j) & 0xFF;
			++result;
		}
	}
}
