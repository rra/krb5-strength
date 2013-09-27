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
heimdal_pwcheck(krb5_context ctx, krb5_principal principal,
                krb5_data *password, const char *tuning UNUSED, char *message,
                size_t length)
{
    krb5_pwqual_moddata data;
    char *pastring;
    char *name = NULL;
    krb5_error_code code;
    const char *error;

    pastring = malloc(password->length + 1);
    if (pastring == NULL) {
        snprintf(message, length, "cannot allocate memory: %s",
                 strerror(errno));
        return 1;
    }
    memcpy(pastring, password->data, password->length);
    pastring[password->length] = '\0';
    code = pwcheck_init(ctx, NULL, &data);
    if (code != 0) {
        error = krb5_get_error_message(ctx, code);
        snprintf(message, length, "cannot initialize strength checking: %s",
                 error);
        krb5_free_error_message(ctx, error);
        free(pastring);
        return 1;
    }
    code = krb5_unparse_name(ctx, principal, &name);
    if (code != 0) {
        error = krb5_get_error_message(ctx, code);
        snprintf(message, length, "cannot unparse principal name: %s", error);
        krb5_free_error_message(ctx, error);
        free(pastring);
        pwcheck_close(ctx, data);
        return 1;
    }
    code = pwcheck_check(ctx, data, pastring, name);
    if (code != 0) {
        error = krb5_get_error_message(ctx, code);
        snprintf(message, length, "%s", error);
        krb5_free_error_message(ctx, error);
    }
    krb5_free_unparsed_name(ctx, name);
    free(pastring);
    pwcheck_close(ctx, data);
    return (code == 0) ? 0 : 1;
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
