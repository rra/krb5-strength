dnl Process this file with autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007, 2009
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([krb5-strength], [0.5], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news silent-rules -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
AC_TYPE_LONG_LONG_INT
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf strlcat strlcpy])

save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [DL_LIBS="$LIBS"])
LIBS="$save_LIBS"
AC_SUBST([DL_LIBS])

RRA_LIB_KRB5

RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([kadm5-pwcheck.h])
AC_CHECK_TYPES([krb5_realm], , , [#include <krb5.h>])
RRA_LIB_KRB5_RESTORE

dnl Create the tests/data directory for builds outside the source directory.
AC_CONFIG_COMMANDS([tests/data/.placeholder], [touch tests/data/.placeholder])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
