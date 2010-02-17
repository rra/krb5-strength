# Automake makefile for krb5-strength.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen cracklib/HISTORY cracklib/LICENCE   \
	cracklib/README cracklib/genrules.pl cracklib/mkdict		    \
	external/heimdal-strength.pod patches/README patches/mit-krb5-1.4.4 \
	tests/TESTS tests/data/wordlist tests/heimdal/external-t	    \
	tests/heimdal/plugin-t tests/heimdal/pod-spelling-t		    \
	tests/heimdal/pod-t tests/mit/plugin-t tests/tap/libtap.sh

# Do this globally.  Everything needs to find the Kerberos headers and
# libraries.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS = $(KRB5_LDFLAGS)

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Build cracklib as a helper library, currently unconditionally, and build
# (but don't install) the packer program.
noinst_LTLIBRARIES = cracklib/libcracklib.la portable/libportable.la
cracklib_libcracklib_la_SOURCES = cracklib/fascist.c cracklib/packlib.c \
	cracklib/rules.c cracklib/stringlib.c
cracklib_libcracklib_la_CPPFLAGS = -DIN_CRACKLIB
noinst_PROGRAMS = cracklib/packer
cracklib_packer_SOURCES = cracklib/packer.c cracklib/packer.h
cracklib_packer_LDADD = cracklib/libcracklib.la
portable_libportable_la_SOURCES = portable/dummy.c portable/macros.h \
        portable/stdbool.h portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS)

# Rules for building the password strength plugin.
module_LTLIBRARIES = plugin/passwd_strength.la
plugin_passwd_strength_la_SOURCES = plugin/api.c plugin/heimdal.c plugin/mit.c
plugin_passwd_strength_la_LDFLAGS = -module -avoid-version
plugin_passwd_strength_la_LIBADD = cracklib/libcracklib.la \
	portable/libportable.la

# The Heimdal external-check program.
bin_PROGRAMS = external/heimdal-strength
external_heimdal_strength_CFLAGS = $(AM_CFLAGS)
external_heimdal_strength_SOURCES = plugin/api.c plugin/api.h \
	external/heimdal-strength.c
external_heimdal_strength_LDADD = cracklib/libcracklib.la \
	portable/libportable.la $(KRB5_LIBS)
dist_man_MANS = external/heimdal-strength.1

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.  This breaks the GNU coding standard, but in this area the GNU
# coding standard is dumb.
CLEANFILES = tests/data/dictionary.hwm tests/data/dictionary.pwd \
	tests/data/dictionary.pwi
DISTCLEANFILES = tests/data/.placeholder
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
        configure

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on.
WARNINGS = -g -O -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/heimdal/plugin tests/mit/plugin			 \
	tests/portable/asprintf-t tests/portable/snprintf-t		 \
	tests/portable/strlcat-t tests/portable/strlcpy-t tests/runtests
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h

tests_heimdal_plugin_SOURCES = tests/heimdal/plugin.c
tests_heimdal_plugin_LDADD = portable/libportable.la $(KRB5_LIBS) $(DL_LIBS)
tests_mit_plugin_SOURCES = tests/mit/plugin.c
tests_mit_plugin_LDADD = portable/libportable.la $(KRB5_LIBS) $(DL_LIBS)
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
	tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
	tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a portable/libportable.la

tests/data/dictionary.pwd: cracklib/packer $(srcdir)/tests/data/wordlist
	cracklib/packer tests/data/dictionary < $(srcdir)/tests/data/wordlist

check-local: $(check_PROGRAMS) tests/data/dictionary.pwd
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
