# Automake makefile for krb5-strength.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen cracklib/HISTORY cracklib/LICENCE cracklib/README \
	cracklib/mkdict patches/README patches/mit-krb5-1.4.4

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Build cracklib as a helper library, currently unconditionally, and build
# (but don't install) the packer program.
noinst_LTLIBRARIES = cracklib/libcracklib.la
cracklib_libcracklib_la_SOURCES = cracklib/fascist.c cracklib/packlib.c \
	cracklib/rules.c cracklib/stringlib.c
cracklib_libcracklib_la_CPPFLAGS = -DIN_CRACKLIB
noinst_PROGRAMS = cracklib/packer
cracklib_packer_SOURCES = cracklib/packer.c cracklib/packer.h
cracklib_packer_LDADD = cracklib/libcracklib.la

# Rules for building the password strength plugin.
module_LTLIBRARIES = plugin/passwd_strength.la
plugin_passwd_strength_la_SOURCES = plugin/api.c
plugin_passwd_strength_la_LDFLAGS = -module -avoid-version
plugin_passwd_strength_la_LIBADD = cracklib/libcracklib.la

# The Heimdal external-check program.
bin_PROGRAMS = plugin/heimdal-strength
plugin_heimdal_strength_CFLAGS = $(AM_CFLAGS)
plugin_heimdal_strength_SOURCES = plugin/api.c plugin/api.h \
	plugin/heimdal-strength.c
plugin_heimdal_strength_LDADD = cracklib/libcracklib.la $(KRB5_LIBS)

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.  This breaks the GNU coding standard, but in this area the GNU
# coding standard is dumb.
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
