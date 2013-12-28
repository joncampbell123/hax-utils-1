
#include <stdint.h>

/* This is 32-bit code. Compile with GCC (GNU Compiler Collection) targeting 32-bit x86 (i386) */

/* WARNING: GCC by default does not use leading underscore.
 *          Make sure the Makefile uses -fleading-underscore so Watcom can find it */

const char function1_message[] = "Hello world. I was compiled with GCC i386";

unsigned int function1_gcc() {
	return 0xABCD1234;
}

