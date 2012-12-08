# Target: Linux
# Compiler: GCC

builddir=linux-$(shell uname -m)
bindir=$(builddir)/bin
objdir=$(builddir)/obj
outputs=$(bindir)/info
prefix=/usr/hax-utils-1/filefmt/exe/msdosexe
MY_CFLAGS=-g0 -Os -fomit-frame-pointer -DLINUX=1 -Wall -pedantic -I../../..
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

$(bindir)/info: $(objdir)/info.o $(objdir)/exerange.o
	$(CC) $(MY_LDFLAGS) $(LDFLAGS) -o $@ $^

$(objdir)/info.o: info.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

$(objdir)/exerange.o: exerange.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -c -o $@ $<

