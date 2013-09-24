/*
 * Type definition for password test data.
 *
 * This header provides the struct definition for password test data written
 * out by make-c-data.  It's included by the test data files.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>

#include <kadm5/kadm5_err.h>

/* Heimdal doesn't define KADM5_PASS_Q_GENERIC. */
#ifndef KADM5_PASS_Q_GENERIC
# define KADM5_PASS_Q_GENERIC KADM5_PASS_Q_DICT
#endif

struct password_test {
    const char *name;
    const char *principal;
    const char *password;
    krb5_error_code code;
    const char *error;
};
