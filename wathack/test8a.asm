
segment _TEXT class=CODE USE32

segment _DATA class=DATA USE32

global _this_is_arbitrary_data
_this_is_arbitrary_data:	db	'This is an arbitrary string',0

segment _BSS class=BSS USE32

global _this_is_arbitrary_stack_data
_this_is_arbitrary_stack_data:	resd	1

group DGROUP _DATA _BSS

