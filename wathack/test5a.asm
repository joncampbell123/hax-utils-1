
segment _TEXT class=CODE USE32	; <- The Watcom linker will gripe about sticking 32-bit code into 16-bit like this
				;    The weird thing is that it will then insert it at 0000:0000 in the EXE image

global _function1_32
_function1_32:	nop
		nop
		nop
		nop
		nop
		push	eax
		pop	eax
		ret

segment _DATA class=DATA	; <- We can't USE32 the data segment because WLINK will not mix USE16 and USE32

segment _BSS class=BSS

group DGROUP _DATA _BSS

