
segment _TEXT class=CODE USE16 ; Apparently Watcom Linker will link 16-bit code into a 32-bit DOS program without complaint!

global _function1_16
_function1_16:	nop
		nop
		nop
		nop
		nop
		push	ax
		pop	ax
		ret

segment _DATA class=DATA USE32	; Watcom Linker will NOT combine 16-bit and 32-bit segments!

segment _BSS class=BSS USE32

group DGROUP _DATA _BSS

