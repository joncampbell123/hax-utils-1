#include <stdio.h>
#include <stdint.h>
#include <i86.h>

extern const char function1_message[];
void __cdecl function1_16();

int main() {
	unsigned char *p;
	unsigned int i;

	printf("Our 16-bit sub: %04x:%04x\n",FP_SEG(function1_16),FP_OFF(function1_16));
	printf("Our main(): %04x:%04x\n",FP_SEG(main),FP_OFF(main));
	p = (unsigned char*)function1_16;
	for (i=0;i < 16;i++) printf("%02X ",p[i]);
	printf("\n");

	printf("Our 16-bit string: %04x:%04x\n",FP_SEG(function1_message),FP_OFF(function1_message));
	printf("It says: %Fs\n",function1_message);

	return 0;
}
