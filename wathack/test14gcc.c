
#include <stdint.h>

/* This is 32-bit code. Compile with GCC (GNU Compiler Collection) targeting 32-bit x86 (i386) */

/* WARNING: GCC by default does not use leading underscore.
 *          Make sure the Makefile uses -fleading-underscore so Watcom can find it */

const char function1_message[] = "Hello world. I was compiled with GCC i386";
const char crlf[] = "\r\n";

void int10_put(unsigned char c) {
	__asm__ __volatile__ (	"	movb	%0,%%al\n"
				"	movb	$0x0E,%%ah\n"
				"	xorl	%%ebx,%%ebx\n"
				"	int	$0x10" : /* out */ : "g" (c) /* in */ : "eax", "ebx" /* clobber */);
}

unsigned int function1_gcc(const char *str,unsigned int val) {
	const char *s;

	s=str;
	while (*s) int10_put(*s++);

	s=function1_message;
	while (*s) int10_put(*s++);
	s=crlf;
	while (*s) int10_put(*s++);

	return val;
}

