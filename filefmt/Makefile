subdirs=exe

all:
	for i in $(subdirs); do make -C $$i || break; done

clean:
	for i in $(subdirs); do make -C $$i clean || break; done

distclean:
	for i in $(subdirs); do make -C $$i distclean || break; done

