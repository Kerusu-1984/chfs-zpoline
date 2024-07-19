AC_PREREQ([2.69])
AC_INIT([cz] [0.1], [miyauchi@hpcs.cs.tsukuba.ac.jp])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_COMMANDS([init_submodules],
  [if test -d .git; then
     git submodule update --init --recursive
   fi])

AC_PROG_CC
AC_ENABLE_SHARED
AC_DISABLE_STATIC
LT_INIT

PKG_CHECK_MODULES([CHFS], [chfs])
AC_CHECK_HEADERS([dis-asm.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
