bits 16

segment _TEXT class=CODE

segment _DATA class=DATA

global _this_is_arbitrary_data
_this_is_arbitrary_data:	db	'This is an arbitrary string',0

global _this_is_an_exe_image
_this_is_an_exe_image:
incbin "wat/bin/test2.exe"
global _this_is_an_exe_image_size
_this_is_an_exe_image_size:	dw	$ - _this_is_an_exe_image

segment _BSS class=BSS

group DGROUP _DATA _BSS

