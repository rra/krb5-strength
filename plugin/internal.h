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
#include <portable/macros.h>

#ifdef HAVE_CDB_H
# include <cdb.h>
#endif

#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#else
typedef struct krb5_pwqual_moddata_st *krb5_pwqual_moddata;
#endif

/* Error strings returned (and displayed to the user) for various failures. */
#define ERROR_ASCII    "password contains non-ASCII or control characters"
#define ERROR_DICT     "password is based on a dictionary word"
#define ERROR_LETTER   "password is only letters and spaces"
#define ERROR_SHORT    "password is too short"
#define ERROR_USERNAME "password based on username"

/*
 * MIT Kerberos uses this type as an abstract data type for any data that a
 * password quality check needs to carry.  Reuse it since then we get type
 * checking for at least the MIT plugin.
 */
struct krb5_pwqual_moddata_st {
    long minimum_length;        /* Minimum password length */
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
krb5_error_code strength_init(krb5_context, const char *dictionary,
                              krb5_pwqual_moddata *);

/*
 * Check a password.  Returns 0 if okay.  On error, sets the Kerberos error
 * message and returns a Kerberos status code.
 */
krb5_error_code strength_check(krb5_context, krb5_pwqual_moddata,
                               const char *password, const char *principal);

/* Free the subset of internal data used by the CDB dictionary checks. */
void strength_close_cdb(krb5_context, krb5_pwqual_moddata);

/*
 * CDB handling.  strength_init_cdb gets the dictionary configuration and sets
 * up the CDB database, strength_check_cdb checks it, and strength_close_cdb
 * handles freeing resources.
 *
 * If not built with CDB support, provide some stubs for check and close.
 * init is always a real function, which reports an error if CDB is
 * requested.
 */
krb5_error_code strength_init_cdb(krb5_context, krb5_pwqual_moddata);
#ifdef HAVE_CDB
krb5_error_code strength_check_cdb(krb5_context, krb5_pwqual_moddata,
                                   const char *password);
void strength_close(krb5_context, krb5_pwqual_moddata);
#else
# define strength_check_cdb(c, d, p) 0
# define strength_close_cdb(c, d)    /* empty */
#endif

/*
 * CrackLib handling.  strength_init_cracklib gets the dictionary
 * configuration does some sanity checks on it, and strength_check_cracklib
 * checks the password against CrackLib.
 */
krb5_error_code strength_init_cracklib(krb5_context, krb5_pwqual_moddata,
                                       const char *dictionary);
krb5_error_code strength_check_cracklib(krb5_context, krb5_pwqual_moddata,
                                        const char *password);

/*
 * Obtain configuration settings from krb5.conf.  These are wrappers around
 * the krb5_appdefault_* APIs that handle setting the section name, obtaining
 * the local default realm and using it to find settings, and doing any
 * necessary conversion.
 */
void strength_config_boolean(krb5_context, const char *, bool *)
    __attribute__((__nonnull__));
void strength_config_number(krb5_context, const char *, long *)
    __attribute__((__nonnull__));
void strength_config_string(krb5_context, const char *, char **)
    __attribute__((__nonnull__));

/*
 * Store a particular password quality error in the Kerberos context.  The
 * _system variant uses errno for the error code and appends the strerror
 * results to the message.  All versions return the error code set.
 */
krb5_error_code strength_error_class(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_dict(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_generic(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_system(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code strength_error_tooshort(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PLUGIN_INTERNAL_H */
