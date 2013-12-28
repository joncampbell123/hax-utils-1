# Target: Linux
# Compiler: GCC

builddir=wat
bindir=$(builddir)/bin
objdir=$(builddir)/obj

all: $(builddir) $(bindir) $(objdir) $(bindir)/test1.exe $(bindir)/test2.exe $(bindir)/test3.exe $(bindir)/test4.exe $(bindir)/test5.exe $(bindir)/test6.exe $(bindir)/test7.exe $(bindir)/test8.exe $(bindir)/test9.exe $(bindir)/test10.exe $(bindir)/test11.exe $(bindir)/test12.exe $(bindir)/test13.exe $(bindir)/dos4gw.exe

$(bindir)/dos4gw.exe: dos4gw.dat
	cp -v dos4gw.dat $(bindir)/dos4gw.exe

$(bindir)/test13.exe: $(objdir)/test13.obj $(objdir)/test13gcc.o
	@echo option quiet system dos4g file $(objdir)/test13gcc.o file $(objdir)/test13.obj option artificial option eliminate option map=$(objdir)/test13.map name $@ >$(objdir)/test13.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test13.lnk

$(objdir)/test13gcc.o: test13gcc.c
	gcc -fleading-underscore -mincoming-stack-boundary=2 -mpreferred-stack-boundary=2 -mstackrealign -march=i386 -g0 -Os -c -o $@ $^

$(objdir)/test13.obj: test13.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test12.exe: $(objdir)/test12.obj $(objdir)/test12gcc.o
	@echo option quiet system dos4g file $(objdir)/test12gcc.o file $(objdir)/test12.obj option artificial option eliminate option map=$(objdir)/test12.map name $@ >$(objdir)/test12.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test12.lnk

# in this hack we use the Watcom linker to compile the main function (with Watcom C) and additional functions (with GCC)
# Note that GCC 4.5 and later assume 16-byte stack alignment, so for Watcom interop we have to explicitly tell it to
# target a 386 and assume/work with 4-byte stack alignment. If actually used in a Linux program it becomes ABI compatible,
# but we're targeting Watcom C + DOS 32-bit, so who cares?
$(objdir)/test12gcc.o: test12gcc.c
	gcc -fleading-underscore -mincoming-stack-boundary=2 -mpreferred-stack-boundary=2 -mstackrealign -march=i386 -g0 -Os -c -o $@ $^

$(objdir)/test12.obj: test12.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test11.exe: $(objdir)/test11.obj $(objdir)/test11a.obj
	@echo option quiet system dos4g file $(objdir)/test11a.obj file $(objdir)/test11.obj option artificial option eliminate option map=$(objdir)/test11.map name $@ >$(objdir)/test11.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test11.lnk

# Note our hack to MAKE the linker take it: wcc386 by default uses "CODE" "DATA" etc for
# section/segment names. It will NOT mix 16-bit and 32-bit segments! So we rename the sections.
# we also remove stack checks (-s) to avoid "undefined __CHK" errors.
# we also enforce inline 80x87 to avoid linking to the 8087 emulation.
$(objdir)/test11a.obj: test11a.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -nd=DATA16 -s -fpi87 -ms -zu -fo=$(objdir)/.obj $^

$(objdir)/test11.obj: test11.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test10.exe: $(objdir)/test10.obj $(objdir)/test10a.obj
	@echo option quiet system dos4g file $(objdir)/test10a.obj file $(objdir)/test10.obj option map=$(objdir)/test10.map name $@ >$(objdir)/test10.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test10.lnk

# Note our hack to MAKE the linker take it: wcc386 by default uses "CODE" "DATA" etc for
# section/segment names. It will NOT mix 16-bit and 32-bit segments! So we rename the sections.
# we also remove stack checks (-s) to avoid "undefined __CHK" errors.
# we also enforce inline 80x87 to avoid linking to the 8087 emulation.
$(objdir)/test10a.obj: test10a.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -nd=DATA16 -s -fpi87 -fo=$(objdir)/.obj $^

$(objdir)/test10.obj: test10.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test9.exe: $(objdir)/test9.obj $(objdir)/test9a.obj
	@echo option quiet system dos4g file $(objdir)/test9a.obj file $(objdir)/test9.obj option map=$(objdir)/test9.map name $@ >$(objdir)/test9.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test9.lnk

$(objdir)/test9a.obj: test9a.asm
	nasm -o $@ -f obj $^

$(objdir)/test9.obj: test9.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test8.exe: $(objdir)/test8.obj $(objdir)/test8a.obj
	@echo option quiet system dos4g file $(objdir)/test8a.obj file $(objdir)/test8.obj option map=$(objdir)/test8.map name $@ >$(objdir)/test8.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test8.lnk

$(objdir)/test8a.obj: test8a.asm
	nasm -o $@ -f obj $^

$(objdir)/test8.obj: test8.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test7.exe: $(objdir)/test7.obj
	@echo option quiet system dos4g file $(objdir)/test7.obj option map=$(objdir)/test7.map name $@ >$(objdir)/test7.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test7.lnk

$(objdir)/test7.obj: test7.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -fo=$(objdir)/.obj $^


$(bindir)/test6.exe: $(objdir)/test6.obj $(objdir)/test6a.obj
	@echo option quiet system dos file $(objdir)/test6a.obj file $(objdir)/test6.obj option map=$(objdir)/test6.map name $@ >$(objdir)/test6.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test6.lnk

# Note our hack to MAKE the linker take it: wcc386 by default uses "CODE" "DATA" etc for
# section/segment names. It will NOT mix 16-bit and 32-bit segments! So we rename the sections.
# we also remove stack checks (-s) to avoid "undefined __CHK" errors.
# we also enforce inline 80x87 to avoid linking to the 8087 emulation.
$(objdir)/test6a.obj: test6a.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc386 -nc=CODE32 -nd=DATA32 -nt=CODE32 -s -fpi87 -fo=$(objdir)/.obj $^

$(objdir)/test6.obj: test6.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(bindir)/test5.exe: $(objdir)/test5.obj $(objdir)/test5a.obj
	@echo option quiet system dos file $(objdir)/test5a.obj file $(objdir)/test5.obj option map=$(objdir)/test5.map name $@ >$(objdir)/test5.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test5.lnk

$(objdir)/test5a.obj: test5a.asm
	nasm -o $@ -f obj $^

$(objdir)/test5.obj: test5.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(bindir)/test4.exe: $(objdir)/test4.obj $(objdir)/test4a.obj
	@echo option quiet system dos file $(objdir)/test4a.obj file $(objdir)/test4.obj option map=$(objdir)/test4.map name $@ >$(objdir)/test4.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test4.lnk

$(objdir)/test4a.obj: test4a.asm
	nasm -o $@ -f obj $^

$(objdir)/test4.obj: test4.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(bindir)/test3.exe: $(objdir)/test3.obj $(objdir)/test3a.obj
	@echo option quiet system dos file $(objdir)/test3a.obj file $(objdir)/test3.obj option map=$(objdir)/test3.map name $@ >$(objdir)/test3.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test3.lnk

# test3a.asm inserts the contents of test2.exe into the EXE image
$(objdir)/test3a.obj: test3a.asm $(bindir)/test2.exe
	nasm -o $@ -f obj test3a.asm

$(objdir)/test3.obj: test3.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(bindir)/test2.exe: $(objdir)/test2.obj $(objdir)/test2a.obj
	@echo option quiet system dos file $(objdir)/test2a.obj file $(objdir)/test2.obj option map=$(objdir)/test2.map name $@ >$(objdir)/test2.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test2.lnk

$(objdir)/test2a.obj: test2a.asm
	nasm -o $@ -f obj $^

$(objdir)/test2.obj: test2.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(bindir)/test1.exe: $(objdir)/test1.obj
	@echo option quiet system dos file $(objdir)/test1.obj option map=$(objdir)/test1.map name $@ >$(objdir)/test1.lnk
	. ../linux-ow.sh ; /usr/watcom/binl/wlink @$(objdir)/test1.lnk

$(objdir)/test1.obj: test1.c
	. ../linux-ow.sh ; /usr/watcom/binl/wcc -fo=$(objdir)/.obj $^


$(builddir):
	mkdir -p $(builddir)

$(bindir):
	mkdir -p $(bindir)

$(objdir):
	mkdir -p $(objdir)

clean:
	rm -f $(objdir)/* $(bindir)/*
	rmdir -p $(objdir) $(bindir) || true

install:

distclean: clean
	rm -Rf $(builddir)

