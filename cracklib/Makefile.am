EXTRA_DIST=mkdict builddict.sh
AM_CFLAGS = -DSBINDIR=\"@sbindir@\"

moduledir = $(prefix)/var/krb5kdc
module_LTLIBRARIES = kadmin_plugin.la

kadmin_plugin_la_SOURCES = kadmin_plugin.c fascist.c packlib.c rules.c stringlib.c packer.h
kadmin_plugin_la_LDFLAGS = -module -avoid-version
kadmin_plugin_la_CFLAGS = $(AM_CFLAGS) -DIN_CRACKLIB

packer_SOURCES = packer.c packlib.c packer.h stringlib.c
bin_PROGRAMS = packer

