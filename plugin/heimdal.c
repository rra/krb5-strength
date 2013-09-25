/*
 * Heimdal shared module API.
 *
 * This is the glue required for a Heimdal password quality check via a
 * dynamically loaded module.  Heimdal's shared module API doesn't have
 * separate initialization and shutdown functions, so provide a self-contained
 * function that looks up the dictionary path from krb5.conf and does all the
 * work.  This means that it does memory allocations on every call, which
 * isn't ideal, but it's probably not that slow.
 *
 * Of course, the external Heimdal strength checking program can be used
 * instead.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2009, 2013
 *     The Board of Trustees of the Leland Stanford Junior Unversity
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>

#include <plugin/api.h>
#include <util/macros.h>

/* Skip this entire file if not building with Heimdal. */
#ifdef HAVE_KRB5_REALM

/* kadm5/kadm5-pwcheck.h isn't always installed by Heimdal. */
# ifdef HAVE_KADM5_KADM5_PWCHECK_H
#  include <kadm5/kadm5-pwcheck.h>
# else
#  define KADM5_PASSWD_VERSION_V1 1

typedef int
(*kadm5_passwd_quality_check_func)(krb5_context context,
                                   krb5_principal principal,
                                   krb5_data *password,
                                   const char *tuning,
                                   char *message,
                                   size_t length);

struct kadm5_pw_policy_check_func {
    const char *name;
    kadm5_passwd_quality_check_func func;
};

struct kadm5_pw_policy_verifier {
    const char *name;
    int version;
    const char *vendor;
    const struct kadm5_pw_policy_check_func *funcs;
};
# endif /* !HAVE_KADM5_PWCHECK_H */

/*
 * This is the single check function that we provide.  It does the glue
 * required to initialize our checks, convert the Heimdal arguments to the
 * strings we expect, and return the result.
 */
static int
heimdal_pwcheck(krb5_context context, krb5_principal principal,
                krb5_data *password, const char *tuning UNUSED, char *message,
                size_t length)
{
    void *data;
    char *pastring;
    char *name = NULL;
    char *dictionary = NULL;
    krb5_error_code status;
    int result;

    krb5_appdefault_string(context, "krb5-strength", principal->realm,
                           "password_dictionary", "", &dictionary);
    if (dictionary == NULL || dictionary[0] == '\0') {
        strlcpy(message, "password_dictionary not configured in krb5.conf",
                length);
        return 1;
    }
    status = krb5_unparse_name(context, principal, &name);
    if (status != 0) {
        strlcpy(message, "Cannot unparse principal name", length);
        return 1;
    }
    pastring = malloc(password->length + 1);
    if (pastring == NULL) {
        snprintf(message, length, "Cannot allocate memory: %s",
                 strerror(errno));
        return 1;
    }
    memcpy(pastring, password->data, password->length);
    pastring[password->length] = '\0';
    if (pwcheck_init(&data, dictionary) != 0) {
        snprintf(message, length, "Cannot initialize strength checking"
                 " with dictionary %s: %s", dictionary, strerror(errno));
        free(pastring);
        return 1;
    }
    result = pwcheck_check(data, pastring, name, message, length);
    krb5_free_unparsed_name(ctx, name);
    free(pastring);
    pwcheck_close(data);
    return (result == 0) ? 0 : 1;
}

/* The public symbol that Heimdal looks for. */
static struct kadm5_pw_policy_check_func functions[] = {
    { "krb5-strength", heimdal_pwcheck },
    { NULL, NULL }
};
struct kadm5_pw_policy_verifier kadm5_password_verifier = {
    "krb5-strength",
    KADM5_PASSWD_VERSION_V1,
    "Russ Allbery",
    functions
};

#endif /* HAVE_KRB5_REALM */
