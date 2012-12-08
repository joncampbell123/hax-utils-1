# Target: Linux
# Compiler: GCC

builddir=linux-$(shell uname -m)
outputs=$(builddir)/info
MY_CFLAGS=-g3 -O0 -fno-omit-frame-pointer -DLINUX=1 -Wall -pedantic
CC=gcc

all: $(builddir) $(outputs)

$(builddir):
	mkdir -p $(builddir)

clean:
	rm -f $(outputs)
	rmdir $(builddir)

distclean: clean
	rm -Rf $(builddir)

$(builddir)/info: info.c
	$(CC) $(MY_CFLAGS) $(CFLAGS) -o $@ $<

