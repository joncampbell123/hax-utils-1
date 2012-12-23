bits 16

segment _TEXT class=CODE

segment _DATA class=DATA

global _this_is_arbitrary_data
_this_is_arbitrary_data:	db	'This is an arbitrary string',0

segment _BSS class=BSS

global _this_is_arbitrary_stack_data
_this_is_arbitrary_stack_data:	resw	1

group DGROUP _DATA _BSS

