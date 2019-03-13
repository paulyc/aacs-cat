all: main.c
	gcc -g -I../libaacs/src src/main.cpp -o aacs-find-vuk ../libaacs/src/libaacs/.libs/*.o ../libaacs/src/util/.libs/*.o ../libaacs/src/file/.libs/*.o -lgcrypt -lgpg-error
