#include <stdio.h>
#include <stdint.h>
#include <i86.h>

/* NOTE: References must be treated as FAR because Watcom will NOT combine 16-bit and 32-bit
 *       code and data into one segment */
extern const char far function1_message[];
void __cdecl far function1_32();

int main() {
	unsigned char far *p;
	unsigned int i;

	printf("Our 32-bit sub: %04x:%04x\n",FP_SEG(function1_32),FP_OFF(function1_32));
	printf("Our main(): %04x:%04x\n",FP_SEG(main),FP_OFF(main));
	p = (unsigned char far*)function1_32;
	for (i=0;i < 16;i++) printf("%02X ",p[i]);
	printf("\n");

	printf("Our 32-bit string: %04x:%04x\n",FP_SEG(function1_message),FP_OFF(function1_message));
	printf("It says: %Fs\n",function1_message);

	return 0;
}
