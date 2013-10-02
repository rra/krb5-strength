/*
 * Prototypes for the kadmin password strength checking plugin.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University.
 * Extensive modifications by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior Unversity
 *
 * See LICENSE for licensing terms.
 */

#ifndef PLUGIN_INTERNAL_H
#define PLUGIN_INTERNAL_H 1

#include <config.h>
#include <portable/krb5.h>

#ifdef HAVE_CDB_H
# include <cdb.h>
#endif

#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#else
typedef struct krb5_pwqual_moddata_st *krb5_pwqual_moddata;
#endif

/*
 * MIT Kerberos uses this type as an abstract data type for any data that a
 * password quality check needs to carry.  Reuse it since then we get type
 * checking for at least the MIT plugin.
 */
struct krb5_pwqual_moddata_st {
    long min_length;            /* Minimum password length */
    bool ascii;                 /* Whether to require printable ASCII */
    bool nonletter;             /* Whether to require a non-letter */
    char *dictionary;           /* Base path to CrackLib dictionary */
    bool have_cdb;              /* Whether we have a CDB dictionary */
    int cdb_fd;                 /* File descriptor of CDB dictionary */
#ifdef HAVE_CDB_H
    struct cdb cdb;             /* Open CDB dictionary data */
#endif
};

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* Initialize the plugin and set up configuration. */
krb5_error_code pwcheck_init(krb5_context, const char *dictionary,
                             krb5_pwqual_moddata *);

/*
 * Check a password.  Returns 0 if okay.  On error, sets the Kerberos error
 * message and returns a Kerberos status code.
 */
krb5_error_code pwcheck_check(krb5_context, krb5_pwqual_moddata,
                              const char *password, const char *principal);

/* Check a password (and some permutations) against a CDB database. */
krb5_error_code pwcheck_check_cdb(krb5_context, krb5_pwqual_moddata,
                                  const char *password);

/* Finished checking passwords.  Free internal data. */
void pwcheck_close(krb5_context, krb5_pwqual_moddata);

/* Free the subset of internal data used by the CDB module. */
void pwcheck_close_cdb(krb5_context, krb5_pwqual_moddata);

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PLUGIN_INTERNAL_H */
