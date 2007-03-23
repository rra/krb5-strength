dnl Process this file with autoconf to produce a configure script.
dnl $Id$
dnl
dnl Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
dnl See README for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.60])
AC_INIT([krb5-strength], [0.3], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([tools])
AC_INIT_AUTOMAKE([1.10 -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

# Crank up the warnings if we're using GCC.
if test "x$GCC" = "xyes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
