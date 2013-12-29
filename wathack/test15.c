#include <stdio.h>
#include <stdint.h>
#include <i86.h>

/* this is 32-bit code. compile with Watcom C (wcc386) */

extern const char function1_message[];
unsigned int __cdecl function1_gcc(const char *str); /* NTS: GCC is said to use __cdecl as well, so... */

extern unsigned long long watcall_res;

unsigned int __watcall return_watcall(unsigned int x) {
	printf("return_watcall() called! x=0x%08lx\n",x);
	return 0x2345;
}

void __watcall return_watcall_nr(unsigned int x) {
	printf("return_watcall_nr() called! x=0x%08lx\n",x);
}

unsigned long long __watcall return_watcall_4i(unsigned int a,unsigned int b,unsigned int c,unsigned int d) {
	printf("return_watcall_4i() called! a=0x%08lx b=0x%08lx c=0x%08lx d=0x%08lx\n",a,b,c,d);
	return 0x123456789ABCDEFULL;
}

int main() {
	unsigned char *p;
	unsigned int i;

	printf("Our GCC sub: %04x:%04x\n",FP_SEG(function1_gcc),FP_OFF(function1_gcc));
	printf("Our main(): %04x:%04x\n",FP_SEG(main),FP_OFF(main));
	p = (unsigned char*)function1_gcc;
	for (i=0;i < 16;i++) printf("%02X ",p[i]);
	printf("\n");

	printf("Our GCC string: %04x:%04x\n",FP_SEG(function1_message),FP_OFF(function1_message));
	printf("It says: %Fs\n",function1_message);

	printf("I'm going to call that function. Wish me luck!\n"); fflush(stdout);
	i = function1_gcc("Testing 1 2 3\r\n");
	printf("It returned: 0x%08x\n",i);
	if (i != 0x2345) printf("...which is wrong!\n");

	printf("The 4i call returned: %016llx\n",watcall_res);
	return 0;
}
