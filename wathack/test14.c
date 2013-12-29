#include <stdio.h>
#include <stdint.h>
#include <i86.h>

/* this is 32-bit code. compile with Watcom C (wcc386) */

extern const char function1_message[];
unsigned int __cdecl function1_gcc(const char *str,unsigned int val); /* NTS: GCC is said to use __cdecl as well, so... */

unsigned int chk_stack,ret_stack;

static unsigned int read_stack_ptr();
#pragma aux read_stack_ptr = \
	".386p" \
	"mov eax,esp" value [eax]

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
	chk_stack = read_stack_ptr(); /* FIXME: __asm {} inline causes a GPT??? why?? */
	i = function1_gcc("Testing 1 2 3\r\n",0x2345);
	ret_stack = read_stack_ptr();
	printf("It returned: 0x%08lx\n",i);
	if (i != 0x2345) printf("...which is wrong!\n");
	if (chk_stack != ret_stack)
		printf("...it also returned to caller with the wrong ESP (stack ptr) value! 0x%08lx != 0x%08lx\n",
			chk_stack,ret_stack);

	return 0;
}
