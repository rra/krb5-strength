dnl Find the compiler and linker flags for CrackLib.
dnl
dnl Allows the user to specify that the system CrackLib should be used instead
dnl of the embedded version by using --with-cracklib.  In that case, finds the
dnl compiler and linker flags for that version.  Also provides
dnl --with-cracklib-include and --with-cracklib-lib configure options to
dnl specify non-standard paths to the CrackLib headers and libraries.
dnl
dnl Provides the macro RRA_LIB_CRACKLIB.  If --with-cracklib is not specified,
dnl this macro will set the Automake conditional EMBEDDED_CRACKLIB.  If it is
dnl specified, sets the substitution variables CRACKLIB_CPPFLAGS,
dnl CRACKLIB_LDFLAGS, and CRACKLIB_LIBS.  Also provides
dnl RRA_LIB_CRACKLIB_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl remctl libraries, saving the current values first, and
dnl RRA_LIB_CRACKLIB_RESTORE to restore those settings to before the last
dnl RRA_LIB_CRACKLIB_SWITCH.
dnl
dnl Depends on the lib-helper.m4 framework.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2020 Russ Allbery <eagle@eyrie.org>
dnl Copyright 2010
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.
dnl
dnl SPDX-License-Identifier: FSFULLR

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the CrackLib flags.  Used as a wrapper, with
dnl RRA_LIB_CRACKLIB_RESTORE, around tests.
AC_DEFUN([RRA_LIB_CRACKLIB_SWITCH], [RRA_LIB_HELPER_SWITCH([CRACKLIB])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_CRACKLIB_SWITCH was called).
AC_DEFUN([RRA_LIB_CRACKLIB_RESTORE], [RRA_LIB_HELPER_RESTORE([CRACKLIB])])

dnl Checks if CrackLib is present and sets variables as appropriate.
AC_DEFUN([_RRA_LIB_CRACKLIB_INTERNAL],
[RRA_LIB_HELPER_PATHS([CRACKLIB])
 RRA_LIB_CRACKLIB_SWITCH
 AC_CHECK_LIB([crack], [FascistCheck], [CRACKLIB_LIBS=-lcrack],
    [AC_MSG_ERROR([cannot find usable CrackLib library])])
 AC_CHECK_HEADERS([crack.h])
 AC_DEFINE([HAVE_SYSTEM_CRACKLIB], 1, [Define if using the system CrackLib.])
 RRA_LIB_CRACKLIB_RESTORE])

dnl The main macro.
AC_DEFUN([RRA_LIB_CRACKLIB],
[RRA_LIB_HELPER_VAR_INIT([CRACKLIB])

 AC_ARG_WITH([cracklib],
    [AS_HELP_STRING([--with-cracklib][@<:@=DIR@:>@],
        [Use system CrackLib instead of embedded copy])],
    [AS_IF([test x"$withval" = xno],
        [rra_use_CRACKLIB=false],
        [rra_use_CRACKLIB=true
         AS_IF([test x"$withval" != xyes], [rra_CRACKLIB_root="$withval"])])])
 AC_ARG_WITH([cracklib][-include],
    [AS_HELP_STRING([--with-cracklib-include=DIR],
        [Location of CrackLib headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_CRACKLIB_includedir="$withval"])])
 AC_ARG_WITH([cracklib-lib],
    [AS_HELP_STRING([--with-cracklib-lib=DIR],
        [Location of CrackLib libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_CRACKLIB_libdir="$withval"])])

  AS_IF([test x"$rra_use_CRACKLIB" != xfalse],
     [AS_IF([test x"$rra_use_CRACKLIB" != x], [_RRA_LIB_CRACKLIB_INTERNAL])
      AC_DEFINE([HAVE_CRACKLIB], 1, [Define if CrackLib is available.])])
 AM_CONDITIONAL([EMBEDDED_CRACKLIB], [test x"$rra_use_CRACKLIB" = x])])
