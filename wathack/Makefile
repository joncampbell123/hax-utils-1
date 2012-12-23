# Target: Linux
# Compiler: GCC

builddir=wat
bindir=$(builddir)/bin
objdir=$(builddir)/obj

all: $(builddir) $(bindir) $(objdir) $(bindir)/test1.exe $(bindir)/test2.exe $(bindir)/test3.exe $(bindir)/test4.exe $(bindir)/test5.exe $(bindir)/test6.exe


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

