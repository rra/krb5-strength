/*
 * Prototypes for the kadmin password strength checking plugin.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University.
 * Extensive modifications by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009, 2012
 *     The Board of Trustees of the Leland Stanford Junior Unversity
 *
 * See LICENSE for licensing terms.
 */

#ifndef PLUGIN_INTERNAL_H
#define PLUGIN_INTERNAL_H 1

#include <config.h>

/* General public API. */
int pwcheck_init(void **context, const char *dictionary);
int pwcheck_check(void *context, const char *password, const char *principal,
                  char *errstr, int errstrlen);
void pwcheck_close(void *context);

#endif /* !PLUGIN_INTERNAL_H */
