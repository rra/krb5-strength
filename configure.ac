AC_PREREQ(2.57)
AC_INIT([passwd-strength], [0.2], [shadow (at) dementia (dot) org])
AC_CONFIG_SRCDIR([src/kadmin_plugin.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall])

AM_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CXX

# If using GCC specifiy some additional parameters
if test "x$GCC" = "xyes" ; then
   CFLAGS="$CFLAGS -pipe -Wall"
fi

AC_SUBST(PACKAGE_URL, [http://www.dementia.org/~shadow/passwd-strength/])

CFLAGS="$CFLAGS -L/lib"

# Checks for libraries.

LIBS="$LIBS -ldl"

# Checks for header files.

AC_CHECK_FUNCS([strdup])
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_VPRINTF

AC_CHECK_HEADERS([fcntl.h limits.h syslog.h termios.h])
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_C_CONST

AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_UID_T

AC_CONFIG_FILES([src/Makefile Makefile])
AC_OUTPUT
