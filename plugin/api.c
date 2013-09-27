/*
 * The public APIs of the password strength checking kadmind plugin.
 *
 * Provides the public pwcheck_init, pwcheck_check, and pwcheck_close APIs for
 * the kadmind plugin.
 *
 * Developed by Derrick Brashear and Ken Hornstein of Sine Nomine Associates,
 *     on behalf of Stanford University.
 * Extensive modifications by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior Unversity
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>
#include <errno.h>

#include <plugin/api.h>
#include <util/macros.h>

/* Heimdal doesn't define KADM5_PASS_Q_GENERIC. */
#ifndef KADM5_PASS_Q_GENERIC
# define KADM5_PASS_Q_GENERIC KADM5_PASS_Q_DICT
#endif

/* The public function exported by the cracklib library. */
extern char *FascistCheck(const char *password, const char *dict);


/*
 * Load a string option from Kerberos appdefaults.  Takes the Kerberos
 * context, the section name, the realm, the option, and the result location.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value, so we
 * don't return an error code.
 */
static void
default_string(krb5_context ctx, const char *section, const char *opt,
               char **result)
{
    char *value = NULL;
    char *realm = NULL;
    krb5_error_code code;
#ifdef HAVE_KRB5_REALM
    krb5_const_realm rdata;
#else
    krb5_data realm_struct;
    const krb5_data *rdata;
#endif

    /* Get the default realm.  This is annoying for MIT Kerberos. */
    code = krb5_get_default_realm(ctx, &realm);
    if (code != 0)
        realm = NULL;
#ifdef HAVE_KRB5_REALM
    rdata = realm;
#else
    if (realm == NULL)
        rdata = NULL;
    else {
        rdata = &realm_struct;
        realm_struct.magic = KV5M_DATA;
        realm_struct.data = (void *) realm;
        realm_struct.length = strlen(realm);
    }
#endif

    /* Obtain the string from [appdefaults]. */
    krb5_appdefault_string(ctx, section, rdata, opt, "", &value);

    /* If we got something back, store it in result. */
    if (value != NULL) {
        if (value[0] == '\0')
            free(value);
        else {
            if (*result != NULL)
                free(*result);
            *result = strdup(value);
            krb5_free_string(ctx, value);
        }
    }

    /* Free the realm if we got one. */
    if (realm != NULL)
        krb5_free_default_realm(ctx, realm);
}


/*
 * Initialize the module.  Ensure that the dictionary file exists and is
 * readable and store the path in the module context.  Returns 0 on success,
 * non-zero on failure.  This function returns failure only if it could not
 * allocate memory or internal Kerberos calls that shouldn't fail do.
 *
 * The dictionary file should not include the trailing .pwd extension.
 * Currently, we don't cope with a NULL dictionary path.
 */
krb5_error_code
pwcheck_init(krb5_context ctx, const char *dictionary,
             krb5_pwqual_moddata *data)
{
    char *file;
    char *path = NULL;
    int oerrno;

    /* Use dictionary if given, otherwise get from krb5.conf. */
    if (dictionary == NULL)
        default_string(ctx, "krb5-strength", "password_dictionary", &path);
    else {
        path = strdup(dictionary);
        if (path == NULL) {
            oerrno = errno;
            krb5_set_error_message(ctx, oerrno, "cannot allocate memory");
            return oerrno;
        }
    }

    /* If there is no dictionary, abort our setup with an error. */
    if (path == NULL) {
        krb5_set_error_message(ctx, KADM5_MISSING_CONF_PARAMS,
            "password_dictionary not configured in krb5.conf");
        return KADM5_MISSING_CONF_PARAMS;
    }

    /* Sanity-check the dictionary path. */
    if (asprintf(&file, "%s.pwd", path) < 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, oerrno, "cannot allocate memory");
        free(path);
        return oerrno;
    }
    if (access(file, R_OK) != 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, oerrno, "dictionary %s does not exist",
                               file);
        free(path);
        free(file);
        return oerrno;
    }
    free(file);

    /* Everything looks good.  Allocate and store our internal data. */
    *data = malloc(sizeof(**data));
    if (*data == NULL) {
        oerrno = errno;
        krb5_set_error_message(ctx, oerrno, "cannot allocate memory");
        free(path);
        return oerrno;
    }
    (*data)->dictionary = path;
    return 0;
}


/*
 * Check a given password.  Takes a Kerberos context, our module data, the
 * password, the principal the password is for, and a buffer and buffer length
 * into which to put any failure message.
 */
krb5_error_code
pwcheck_check(krb5_context ctx UNUSED, krb5_pwqual_moddata data,
              const char *password, const char *principal)
{
    char *user, *p;
    const char *q;
    size_t i, j;
    char c;
    int oerrno;
    const char *result;

    /*
     * We get the principal (in krb5_unparse_name format) from kadmind and we
     * want to be sure that the password doesn't match the username, the
     * username reversed, or the username with trailing digits.  We therefore
     * have to copy the string so that we can manipulate it a bit.
     */
    if (strcasecmp(password, principal) == 0) {
        krb5_set_error_message(ctx, KADM5_PASS_Q_GENERIC,
                               "password based on username");
        return KADM5_PASS_Q_GENERIC;
    }
    user = strdup(principal);
    if (user == NULL) {
        oerrno = errno;
        krb5_set_error_message(ctx, oerrno, "cannot allocate memory");
        return oerrno;
    }
    for (p = user; p[0] != '\0'; p++) {
        if (p[0] == '\\' && p[1] != '\0') {
            p++;
            continue;
        }
        if (p[0] == '@') {
            p[0] = '\0';
            break;
        }
    }
    if (strlen(password) == strlen(user)) {
        if (strcasecmp(password, user) == 0) {
            free(user);
            krb5_set_error_message(ctx, KADM5_PASS_Q_GENERIC,
                                   "password based on username");
            return KADM5_PASS_Q_GENERIC;
        }

        /* Check against the reversed username. */
        for (i = 0, j = strlen(user) - 1; i < j; i++, j--) {
            c = user[i];
            user[i] = user[j];
            user[j] = c;
        }
        if (strcasecmp(password, user) == 0) {
            free(user);
            krb5_set_error_message(ctx, KADM5_PASS_Q_GENERIC,
                                   "password based on username");
            return KADM5_PASS_Q_GENERIC;
        }
    }
    if (strlen(password) > strlen(user))
        if (strncasecmp(password, user, strlen(user)) == 0) {
            q = password + strlen(user);
            while (isdigit((int) *q))
                q++;
            if (*q == '\0') {
                free(user);
                krb5_set_error_message(ctx, KADM5_PASS_Q_GENERIC,
                                       "password based on username");
                return KADM5_PASS_Q_GENERIC;
            }
        }
    free(user);
    result = FascistCheck(password, data->dictionary);
    if (result != NULL) {
        krb5_set_error_message(ctx, KADM5_PASS_Q_GENERIC, "%s", result);
        return KADM5_PASS_Q_GENERIC;
    }
    return 0;
}


/*
 * Cleanly shut down the password strength plugin.  The only thing we have to
 * do is free the memory allocated for our internal data.
 */
void
pwcheck_close(krb5_context ctx UNUSED, krb5_pwqual_moddata data)
{
    if (data != NULL) {
        free(data->dictionary);
        free(data);
    }
}
