# Target: Linux
# Compiler: GCC

builddir=wat
bindir=$(builddir)/bin
objdir=$(builddir)/obj

all: $(builddir) $(bindir) $(objdir) $(bindir)/test1.exe $(bindir)/test2.exe $(bindir)/test3.exe


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

