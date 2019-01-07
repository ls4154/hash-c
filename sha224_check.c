#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sha224.h"

#define CHUNK_SIZE 64

byte_t buffer[CHUNK_SIZE];

int main(int argc, char **argv)
{
	int fd = STDIN_FILENO;
	if (argc > 1 && (fd = open(argv[1], O_RDONLY)) < 0) {
		fprintf(stderr, "%s : cannot access '%s'\n", argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}

	struct sha224_ctx ctx;
	sha224_init(&ctx);

	int total = 0;
	int rd = 0;
	while ((rd = read(fd, buffer + total, CHUNK_SIZE - total)) > 0) {
		total += rd;
		if (total >= CHUNK_SIZE) {
			sha224_update(&ctx, buffer);
			total = 0;
		}
	}
	sha224_update_last(&ctx, buffer, total);

	for (int i = 0; i < WORD_CNT - 1; ++i)
		printf("%08x", ctx.h[i]);
	printf("\n");

	return 0;
}

