
segment _TEXT class=CODE
bits 32 ; <- this is how to put 32-bit code into a 16-bit code segment without Watcom linker complaining about it

global _function1_32
_function1_32:	nop
		nop
		nop
		nop
		nop
		push	eax
		pop	eax
		ret

segment _DATA class=DATA

segment _BSS class=BSS

group DGROUP _DATA _BSS

