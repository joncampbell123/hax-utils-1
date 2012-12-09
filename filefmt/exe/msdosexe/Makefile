# Target: Linux
# Compiler: GCC

builddir=linux-$(shell uname -m)
bindir=$(builddir)/bin
objdir=$(builddir)/obj
outputs=$(bindir)/info $(bindir)/neinfo $(bindir)/fcunreal
prefix=/usr/hax-utils-1/filefmt/exe/msdosexe
MY_CFLAGS=-g0 -Os -fomit-frame-pointer -DLINUX=1 -Wall -pedantic -std=gnu99 -I../../..
CC=gcc

all: $(builddir) $(bindir) $(objdir) $(outputs)

$(builddir):
	mkdir -p $(builddir)

$(bindir):
	mkdir -p $(bindir)

$(objdir):
	mkdir -p $(objdir)

clean:
	rm -f $(outputs) $(objdir)/*

install:
	mkdir -p $(DESTDIR)$(prefix)
	cp -v $(outputs) $(DESTDIR)$(prefix)/

distclean: clean
	rm -Rf $(builddir)

$(bindir)/neinfo: $(objdir)/neinfo.o $(objdir)/exerange.o $(objdir)/exeparse.o $(objdir)/stubs.o
	$(CC) $(MY_LDFLAGS) $(LDFLAGS) -o $@ $^

$(objdir)/neinfo.o: neinfo.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(bindir)/fcunreal: $(objdir)/fcunreal.o $(objdir)/exerange.o $(objdir)/exeparse.o
	$(CC) $(MY_LDFLAGS) $(LDFLAGS) -o $@ $^

$(objdir)/fcunreal.o: fcunreal.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(bindir)/info: $(objdir)/info.o $(objdir)/exerange.o $(objdir)/exeparse.o
	$(CC) $(MY_LDFLAGS) $(LDFLAGS) -o $@ $^

$(objdir)/info.o: info.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(objdir)/stubs.o: stubs.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(objdir)/exerange.o: exerange.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(objdir)/exeparse.o: exeparse.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

