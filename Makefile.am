# Makefile.am -- Automake makefile for krb5-strength.
#
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = autogen cracklib/HISTORY cracklib/LICENCE cracklib/README \
	cracklib/mkdict patches/README patches/mit-krb5-1.4.4

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.  This breaks the GNU coding standard, but in this area the GNU
# coding standard is dumb.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
        configure

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
