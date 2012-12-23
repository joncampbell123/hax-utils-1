subdirs=filefmt wathack

all:
	for i in $(subdirs); do make -C $$i || break; done

clean:
	for i in $(subdirs); do make -C $$i clean || break; done

install:
	for i in $(subdirs); do make -C $$i install || break; done

distclean:
	for i in $(subdirs); do make -C $$i distclean || break; done

