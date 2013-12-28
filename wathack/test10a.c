
#include <stdint.h>

const char function1_message[] = "Hello world. I am 16-bit code";

static void another_function() {
	__asm {
		push	si
		push	di
		push	cx
		push	ax
		mov	si,1
		mov	di,2
		mov	cx,3
		mov	ax,4
		pop	ax
		pop	cx
		pop	di
		pop	si
	}
}

void _cdecl function1_16() {
	another_function();
	__asm {
		push	cx
		push	si
		mov	cx,0x1234
		mov	si,offset function1_message
l1:		nop
		loop	l1
		pop	si
		pop	cx
	}
}

