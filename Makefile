.SUFFIXES : .c .o
CC = gcc
CFLAGS = -O2

OBJS_SHA1 = sha1_check.o sha1.o
OBJS_SHA0 = sha1_check.o sha0.o
OBJS_SHA256 = sha256_check.o sha256.o
OBJS_SHA224 = sha224_check.o sha224.o
OBJS_SHA512 = sha512_check.o sha512.o

all : sha1_check sha0_check sha256_check sha224_check sha512_check

sha1_check : $(OBJS_SHA1)
	gcc -o sha1_check $(OBJS_SHA1)

sha0_check : $(OBJS_SHA0)
	gcc -o sha0_check $(OBJS_SHA0)

sha256_check : $(OBJS_SHA256)
	gcc -o sha256_check $(OBJS_SHA256)

sha224_check : $(OBJS_SHA224)
	gcc -o sha224_check $(OBJS_SHA224)

sha512_check : $(OBJS_SHA512)
	gcc -o sha512_check $(OBJS_SHA512)

sha0.o : sha1.c
	gcc -o sha0.o -c sha1.c $(CFLAGS) -DSHA0

clean :
	rm $(OBJS_SHA1) $(OBJS_SHA256) $(OBJS_SHA224) $(OBJS_SHA512)
