

sha1_check : sha1_check.c sha1.c
	gcc -o sha1_check sha1_check.c sha1.c
