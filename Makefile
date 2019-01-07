.SUFFIXES : .c .o
CC = gcc
CFLAGS = -O2

OBJS_SHA1 = sha1_check.o sha1.o
OBJS_SHA256 = sha256_check.o sha256.o
OBJS_SHA224 = sha224_check.o sha224.o

all : sha1_check sha256_check sha224_check

sha1_check : $(OBJS_SHA1)
	gcc -o sha1_check $(OBJS_SHA1)

sha256_check : $(OBJS_SHA256)
	gcc -o sha256_check $(OBJS_SHA256)

sha224_check : $(OBJS_SHA224)
	gcc -o sha224_check $(OBJS_SHA224)

clean :
	rm $(OBJS_SHA1) $(OBJS_SHA256) $(OBJS_SHA224)
