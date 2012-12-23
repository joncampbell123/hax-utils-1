#include <stdio.h>
#include <stdint.h>
#include <i86.h>

void __cdecl function1_32();

int main() {
	/* NTS: The "far" specifier is needed because
	 *      code segment (containing function1_32)
	 *      is not the same as the data segment
	 *      (which "unsigned char *" would refer to) */
	unsigned char far *p;
	unsigned int i;

	printf("Our 32-bit sub: %04x:%04x\n",FP_SEG(function1_32),FP_OFF(function1_32));
	printf("Our main(): %04x:%04x\n",FP_SEG(main),FP_OFF(main));
	p = (unsigned char far*)function1_32;
	for (i=0;i < 16;i++) printf("%02X ",p[i]);
	printf("\n");

	return 0;
}
