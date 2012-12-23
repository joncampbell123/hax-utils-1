# Target: Linux
# Compiler: GCC

builddir=wat
bindir=$(builddir)/bin
objdir=$(builddir)/obj

all: $(builddir) $(bindir) $(objdir) $(bindir)/test1.exe

$(bindir)/test1.exe: $(objdir)/test1.obj
	@echo option quiet system dos file $(objdir)/test1.obj name $@ >$(objdir)/test1.lnk
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

