/* this is 32-bit code */

#include <stdint.h>

const char function1_message[] = "Hello world. I am 32-bit code";

static void another_function() {
	__asm {
		pusha
		mov	esi,1
		mov	edi,2
		mov	ecx,3
		mov	eax,4
		popa
	}
}

void _cdecl function1_32() {
	another_function();
	__asm {
		push	ecx
		push	esi
		mov	ecx,0x12345678
		mov	esi,offset function1_message
l1:		nop
		loop	l1
		pop	esi
		pop	ecx
	}
}

