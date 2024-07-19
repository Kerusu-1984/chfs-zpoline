lib_LTLIBRARIES = libcz.la
libcz_la_SOURCES = libcz.c
libcz_la_LDFLAGS = -shared -fPIC -pthread @CHFS_LIBS@
libcz_la_CPPFLAGS = -g -Wall -pthread @CHFS_CFLAGS@


install-exec-hook:
	make -C zpoline
	$(INSTALL) -m 755 zpoline/libzpoline.so $(prefix)/lib/
