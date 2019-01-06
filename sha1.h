#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

typedef uint8_t byte_t;
typedef uint32_t word_t;
typedef uint64_t len_t;

void sha1(byte_t *msg, len_t len, byte_t *result);

#endif
