lib_LTLIBRARIES = libcz.la
libcz_la_SOURCES = libcz.c
nodist_libcz_la_SOURCES = syscall_string.c
CLEANFILES = $(top_srcdir)/syscall_string.c
libcz_la_LDFLAGS = -shared -fPIC -pthread @CHFS_LIBS@
libcz_la_CPPFLAGS = -g -Wall -pthread @CHFS_CFLAGS@

syscall_string.c: $(top_srcdir)/syscall_string.sh /usr/include/x86_64-linux-gnu/asm/unistd_64.h
	sh $(top_srcdir)/syscall_string.sh > $(top_srcdir)/syscall_string.c

install-exec-hook:
	make -C $(top_srcdir)/zpoline
	$(INSTALL) -m 755 $(top_srcdir)/zpoline/libzpoline.so $(prefix)/lib/
