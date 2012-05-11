/*
 * MIT Kerberos shared module API.
 *
 * This is the glue required for a Heimdal password quality check via a
 * dynamically loaded module.  Retrieves the dictionary path from krb5.conf.
 * This may change in later versions via a mechanism to pass profile
 * information from kadmind to the plugin.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior Unversity
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <krb5.h>

#include <plugin/api.h>

/* Skip this entire file if building with Heimdal. */
#ifndef HAVE_KRB5_REALM

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED  __attribute__((__unused__))

/* Allow for a build without the plugin header. */
# ifdef HAVE_KRB5_PWCHECK_PLUGIN_H
#  include <krb5/pwcheck_plugin.h>
# else
typedef struct krb5plugin_kadmin_pwcheck_ftable_v0 {
    int minor_version;
    krb5_error_code (*init)(krb5_context, void **);
    void (*fini)(krb5_context, void *);
    int (*check)(krb5_context, void *, krb5_const_principal,
                 const krb5_data *password);
} krb5plugin_kadmin_pwcheck_ftable_v0;
# endif /* !HAVE_KRB5_PWCHECK_PLUGIN_H */


/*
 * Initialize the library.  We can't just call pwcheck_init, since currently
 * kadmind doesn't tell us the dictionary path.  So first look up where the
 * dictionary is, and then call pwcheck_init.
 */
static krb5_error_code
init(krb5_context context, void **data)
{
    char *dictionary = NULL;

    krb5_appdefault_string(context, "krb5-strength", NULL,
                           "password_dictionary", "", &dictionary);
    if (dictionary == NULL || dictionary[0] == '\0') {
        krb5_set_error_message(context, KRB5_PLUGIN_OP_NOTSUPP,
                               "password_dictionary not configured in"
                               " krb5.conf");
        return KRB5_PLUGIN_OP_NOTSUPP;
    }
    if (pwcheck_init(data, dictionary) != 0) {
        krb5_set_error_message(context, errno, "Cannot initialize strength"
                               " checking with dictionary %s: %s", dictionary,
                               strerror(errno));
        return errno;
    }
    return 0;
}


/*
 * Check the password.  We need to transform the krb5_data struct and the
 * principal passed us by kadmind into nul-terminated strings for our check.
 */
static krb5_error_code
check(krb5_context context, void *data, krb5_const_principal princ,
      const krb5_data *password)
{
    char *pastring;
    char *name = NULL;
    krb5_error_code status;
    char message[BUFSIZ];

    status = krb5_unparse_name(context, princ, &name);
    if (status != 0)
        return status;
    pastring = malloc(password->length + 1);
    if (pastring == NULL) {
        status = errno;
        krb5_set_error_message(context, status, "%s", strerror(status));
        krb5_free_unparsed_name(context, name);
        return status;
    }
    memcpy(pastring, password->data, password->length);
    pastring[password->length] = '\0';
    status = pwcheck_check(data, pastring, name, message, sizeof(message));
    if (status != 0)
        krb5_set_error_message(context, status, "%s", message);
    free(pastring);
    krb5_free_unparsed_name(context, name);
    return status;
}


/*
 * Shut down the library.
 */
static void
fini(krb5_context context UNUSED, void *data)
{
    pwcheck_close(data);
}


/* The public symbol that MIT Kerberos looks for. */
krb5plugin_kadmin_pwcheck_ftable_v0 kadmin_pwcheck_0 = {
    0, init, fini, check
};

#endif /* !HAVE_KRB5_REALM */
