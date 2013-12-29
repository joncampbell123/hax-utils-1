
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

/* under normal circumstances GCC's optimizer will boil this down to the direct x86 instructions
 * necessary to make a __watcall type function call. */
/* unsigned int __watcall return_watcall(unsigned int a); */
static inline unsigned int return_watcall(unsigned int a) {
	unsigned int r;

	/* NTS: Remember __watcall calling convention puts the underscore at the end of the function name! */
	__asm__ __volatile__ (	"	call	return_watcall_"
		: /* out  */ "=a" (r)
		: /* in   */ "a" (a)	/* <- load EAX (first param) with "a" */
		: /* clob */);

	return r;
}

/* under normal circumstances GCC's optimizer will boil this down to the direct x86 instructions
 * necessary to make a __watcall type function call. */
/* void __watcall return_watcall_nr(unsigned int a); */
static inline void return_watcall_nr(unsigned int a) {
	/* NTS: Remember __watcall calling convention puts the underscore at the end of the function name! */
	__asm__ __volatile__ (	"	call	return_watcall_nr_"
		: /* out  */ "=a" (a)	/* <- __watcall will trash EAX, convince GCC of that */
		: /* in   */ "a" (a)	/* <- load EAX (first param) with "a" */
		: /* clob */);
}

/* under normal circumstances GCC's optimizer will boil this down to the direct x86 instructions
 * necessary to make a __watcall type function call. */
/* void __watcall return_watcall_nr(unsigned int a); */
static inline unsigned long long return_watcall_4i(unsigned int a,unsigned int b,unsigned int c,unsigned int d) {
	unsigned long long r;

	/* NTS: Remember __watcall calling convention puts the underscore at the end of the function name! */
	__asm__ __volatile__ (	"	call	return_watcall_4i_"
		: /* out  */ "=A" (r)				/* return value is EDX:EAX */
		: /* in   */ "a" (a), "d" (b), "b" (c), "c" (d)	/* __watcall 4 params EAX, EDX, EBX, ECX */
		: /* clob */);

	return r;
}

unsigned long long watcall_res;

unsigned int function1_gcc(const char *str) {
	unsigned int val;
	const char *s;

	s=str;
	while (*s) int10_put(*s++);

	return_watcall_nr(0x12345678);
	val = return_watcall(0x12345678);
	watcall_res = return_watcall_4i(0x12345678,0xABCDEF,0x87654321,0xFEDCBA);

	s=function1_message;
	while (*s) int10_put(*s++);
	s=crlf;
	while (*s) int10_put(*s++);

	return val;
}

