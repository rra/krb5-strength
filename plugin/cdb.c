/*
 * Check a CDB database for a password or some simple permutations.
 *
 * This file implements a much simpler variation on CrackLib checks intended
 * for use with longer passwords where some of the CrackLib permutations don't
 * make as much sense.  A CDB database with passwords as keys is checked for
 * the password and for variations with one character removed from the start
 * or end, two characters removed from the start, two from the end, or one
 * character from both start and end.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#ifdef HAVE_CDB_H
# include <cdb.h>
#endif
#include <errno.h>

#include <plugin/internal.h>
#include <util/macros.h>

/* Skip the rest of this file if CDB is not available. */
#ifdef HAVE_CDB

/*
 * Macro used to make password checks more readable.  Assumes that the found
 * and fail labels are available for the abort cases of finding a password or
 * failing to look it up.
 */
# define CHECK_PASSWORD(ctx, data, password)                    \
    do {                                                        \
        code = in_cdb_dictionary(ctx, data, password, &found);  \
        if (code != 0)                                          \
            goto fail;                                          \
        if (found)                                              \
            goto found;                                         \
    } while (0)


/*
 * Look up a password in CDB and set the found parameter to true if it is
 * found, false otherwise.  Returns a Kerberos status code, which will be 0 on
 * success and something else on failure.
 */
static krb5_error_code
in_cdb_dictionary(krb5_context ctx, krb5_pwqual_moddata data,
                  const char *password, bool *found)
{
    int status, oerrno;

    status = cdb_find(&data->cdb, password, strlen(password));
    if (status < 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, oerrno, "cannot query CDB database: %s",
                               strerror(oerrno));
        return oerrno;
    } else {
        *found = (status == 1);
        return 0;
    }
}


/*
 * Given a password, try the various transformations that we want to apply and
 * check for each of them in the dictionary.  Returns a Kerberos status code,
 * which will be KADM5_PASS_Q_DICT if the password was found in the
 * dictionary.
 */
krb5_error_code
pwcheck_check_cdb(krb5_context ctx, krb5_pwqual_moddata data,
                  const char *password)
{
    krb5_error_code code;
    bool found;
    char *variant = NULL;
    int oerrno;

    /* Check the basic password. */
    CHECK_PASSWORD(ctx, data, password);

    /* Check with one or two characters removed from the start. */
    if (password[0] != '\0') {
        CHECK_PASSWORD(ctx, data, password + 1);
        if (password[1] != '\0')
            CHECK_PASSWORD(ctx, data, password + 2);
    }

    /*
     * Strip a character from the end and then check both that password and
     * the one with a character taken from the start as well.
     */
    if (strlen(password) > 0) {
        variant = strdup(password);
        if (variant == NULL) {
            oerrno = errno;
            krb5_set_error_message(ctx, oerrno, "cannot allocate memory: %s",
                                   strerror(oerrno));
            return oerrno;
        }
        variant[strlen(variant) - 1] = '\0';
        CHECK_PASSWORD(ctx, data, variant);
        if (variant[0] != '\0')
            CHECK_PASSWORD(ctx, data, variant + 1);

        /* Check the password with two characters removed. */
        if (strlen(password) > 1) {
            variant[strlen(variant) - 1] = '\0';
            CHECK_PASSWORD(ctx, data, variant);
        }
        free(variant);
    }

    /* Password not found. */
    return 0;

found:
    /* We found the password or a variant in the dictionary. */
    if (variant != NULL)
        free(variant);
    krb5_set_error_message(ctx, KADM5_PASS_Q_DICT,
                           "it is based on a dictionary word");
    return KADM5_PASS_Q_DICT;

fail:
    /* Some sort of failure during CDB lookup. */
    if (variant != NULL)
        free(variant);
    return code;
}


/*
 * Free internal TinyCDB state and close the CDB dictionary.
 */
void
pwcheck_close_cdb(krb5_context ctx UNUSED, krb5_pwqual_moddata data)
{
    if (data->have_cdb)
        cdb_free(&data->cdb);
    if (data->cdb_fd != -1)
        close(data->cdb_fd);
}

#endif /* HAVE_CDB */
