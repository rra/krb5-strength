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
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013, 2014
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Stub for strength_init_cdb if not built with CDB support.
 */
#ifndef HAVE_CDB
krb5_error_code
strength_init_cdb(krb5_context ctx, krb5_pwqual_moddata data UNUSED)
{
    char *path = NULL;

    /* Get CDB dictionary path from krb5.conf. */
    strength_config_string(ctx, "password_dictionary_cdb", &path);

    /* If it was set, report an error, since we don't have CDB support. */
    if (path == NULL)
        return 0;
    free(path);
    krb5_set_error_message(ctx, KADM5_BAD_SERVER_PARAMS, "CDB dictionary"
                           " requested but not built with CDB support");
    return KADM5_BAD_SERVER_PARAMS;
}
#endif


/* Skip the rest of this file if CDB is not available. */
#ifdef HAVE_CDB

/*
 * Macros used to make password checks more readable.  Assumes that the found
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
# define CHECK_PASSWORD_VARIANT(ctx, data, template, p)                   \
    do {                                                                  \
        code = variant_in_cdb_dictionary(ctx, data, template, p, &found); \
        if (code != 0)                                                    \
            goto fail;                                                    \
        if (found)                                                        \
            goto found;                                                   \
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
    int status;

    *found = false;
    status = cdb_find(&data->cdb, password, strlen(password));
    if (status < 0)
        return strength_error_system(ctx, "cannot query CDB database");
    else {
        *found = (status == 1);
        return 0;
    }
}


/*
 * Given a password template and a pointer to the character to change, check
 * all versions of that template with that character replaced by all possible
 * printable ASCII characters.  The template will be modified in place to try
 * the various characters.  Sets the found parameter to true if some variation
 * of the template is found, false otherwise.  Returns a Kerberos status code.
 */
static krb5_error_code
variant_in_cdb_dictionary(krb5_context ctx, krb5_pwqual_moddata data,
                          char *template, char *permute, bool *found)
{
    int c;
    krb5_error_code code;

    *found = false;
    for (c = 0; c <= 127; c++)
        if (isprint(c)) {
            *permute = c;
            code = in_cdb_dictionary(ctx, data, template, found);
            if (code != 0 || found)
                return code;
        }
    return 0;
}


/*
 * Initialize the CDB dictionary.  Opens the dictionary and sets up the
 * TinyCDB state.  Returns 0 on success, non-zero on failure (and sets the
 * error in the Kerberos context).  If not built with CDB support, always
 * returns an error.
 */
krb5_error_code
strength_init_cdb(krb5_context ctx, krb5_pwqual_moddata data)
{
    krb5_error_code code;
    char *path = NULL;

    /* Get CDB dictionary path from krb5.conf. */
    strength_config_string(ctx, "password_dictionary_cdb", &path);

    /* If there is no configured dictionary, nothing to do. */
    if (path == NULL)
        return 0;

    /* Open the dictionary and initialize the CDB data. */
    data->cdb_fd = open(path, O_RDONLY);
    if (data->cdb_fd < 0)
        return strength_error_system(ctx, "cannot open dictionary %s", path);
    if (cdb_init(&data->cdb, data->cdb_fd) < 0) {
        code = strength_error_system(ctx, "cannot init dictionary %s", path);
        free(path);
        close(data->cdb_fd);
        data->cdb_fd = -1;
        return code;
    }
    free(path);
    data->have_cdb = true;
    return 0;
}


/*
 * Given a password, try the various transformations that we want to apply and
 * check for each of them in the dictionary.  Returns a Kerberos status code,
 * which will be KADM5_PASS_Q_DICT if the password was found in the
 * dictionary.
 */
krb5_error_code
strength_check_cdb(krb5_context ctx, krb5_pwqual_moddata data,
                   const char *password)
{
    krb5_error_code code;
    bool found;
    size_t length, i;
    char *p;
    char *variant = NULL;

    /* If we have no dictionary, there is nothing to do. */
    if (!data->have_cdb)
        return 0;

    /* Check the basic password. */
    CHECK_PASSWORD(ctx, data, password);

    /* Allocate memory for password variations. */
    length = strlen(password);
    variant = malloc(length + 2);
    if (variant == NULL)
        return strength_error_system(ctx, "cannot allocate memory");

    /* Check all one-character deletions. */
    for (i = 0; i < length; i++) {
        if (i > 0)
            memcpy(variant, password, i);
        if (i < length - 1)
            memcpy(variant + i, password + i + 1, length - i - 1);
        variant[length - 1] = '\0';
        CHECK_PASSWORD(ctx, data, variant);
    }

    /* Check all one-character permutations. */
    memcpy(variant, password, length + 1);
    for (p = variant; *p != '\0'; p++)
        CHECK_PASSWORD_VARIANT(ctx, data, variant, p);

    /* Check all one-character additions. */
    for (i = 0; i <= length; i++) {
        if (i > 0)
            memcpy(variant, password, i);
        if (i < length)
            memcpy(variant + i + 1, password + i, length - i);
        variant[length + 1] = '\0';
        CHECK_PASSWORD_VARIANT(ctx, data, variant, variant + i);
    }

    /*
     * Check the password with first and last, two leading, or two trailing
     * characters removed.
     */
    if (length > 2) {
        memcpy(variant, password + 2, length - 1);
        CHECK_PASSWORD(ctx, data, variant);
        memcpy(variant, password + 1, length - 2);
        variant[length - 2] = '\0';
        CHECK_PASSWORD(ctx, data, variant);
        memcpy(variant, password, length - 2);
        variant[length - 2] = '\0';
        CHECK_PASSWORD(ctx, data, variant);
    }

    /* Password not found. */
    free(variant);
    return 0;

found:
    /* We found the password or a variant in the dictionary. */
    free(variant);
    return strength_error_dict(ctx, ERROR_DICT);

fail:
    /* Some sort of failure during CDB lookup. */
    free(variant);
    return code;
}


/*
 * Free internal TinyCDB state and close the CDB dictionary.
 */
void
strength_close_cdb(krb5_context ctx UNUSED, krb5_pwqual_moddata data)
{
    if (data->have_cdb)
        cdb_free(&data->cdb);
    if (data->cdb_fd != -1)
        close(data->cdb_fd);
}

#endif /* HAVE_CDB */
