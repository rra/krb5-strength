dnl Process this file with autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007, 2009, 2010, 2012, 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([krb5-strength], [1.1], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news dist-xz foreign silent-rules subdir-objects
    -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
AC_PROG_INSTALL
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

RRA_LIB_CRACKLIB
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([kadm5-pwcheck.h krb5/pwcheck_plugin.h])
AC_CHECK_TYPES([krb5_realm], [], [], [RRA_INCLUDES_KRB5])
RRA_LIB_KRB5_RESTORE

save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [DL_LIBS="$LIBS"])
LIBS="$save_LIBS"
AC_SUBST([DL_LIBS])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
AC_TYPE_LONG_LONG_INT
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf strlcat strlcpy])

dnl Create the tests/data directory for builds outside the source directory.
AC_CONFIG_COMMANDS([tests/data/.placeholder], [touch tests/data/.placeholder])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
