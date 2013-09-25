/*
 * Kerberos shared module API for MIT Kerberos 1.9 or later.
 *
 * This is the glue required for a password quality check via a dynamically
 * loaded module using the MIT Kerberos pwqual plugin interface.
 *
 * Written by Greg Hudson <ghudson@mit.edu>
 * Copyright 2010 the Massachusetts Institute of Technology
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#endif

#include <plugin/api.h>
#include <util/macros.h>

/* Skip this entire file if building with Heimdal or pre-1.9 MIT. */
#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H

/* Prototype for the public interface. */
krb5_error_code pwqual_strength_initvt(krb5_context, int, int,
                                       krb5_plugin_vtable);


/*
 * Initialize the library.  We can't just call pwcheck_init, since currently
 * kadmind doesn't tell us the dictionary path.  So first look up where the
 * dictionary is, and then call pwcheck_init.
 */
static krb5_error_code
init(krb5_context context, const char *dict_file, krb5_pwqual_moddata *data)
{
    void *d;
    krb5_error_code code;
    char *dictionary = NULL;

    if (dict_file == NULL)
        dict_file = "";
    krb5_appdefault_string(context, "krb5-strength", NULL,
                           "password_dictionary", dict_file, &dictionary);
    if (dictionary == NULL || dictionary[0] == '\0') {
        krb5_set_error_message(context, KADM5_MISSING_CONF_PARAMS,
                               "Cannot initialize strength checking without"
                               " dictionary");
        krb5_free_string(context, dictionary);
        return KADM5_MISSING_CONF_PARAMS;
    }
    code = pwcheck_init(&d, dictionary);
    if (code != 0) {
        krb5_set_error_message(context, code, "Cannot initialize strength"
                               " checking with dictionary %s: %s", dictionary,
                               strerror(errno));
        krb5_free_string(context, dictionary);
        return code;
    }
    krb5_free_string(context, dictionary);
    *data = d;
    return 0;
}


/*
 * Check the password.  We need to transform the principal passed us by kadmind
 * into a string for our check.
 */
static krb5_error_code
check(krb5_context context, krb5_pwqual_moddata data, const char *password,
      const char *policy_name UNUSED, krb5_principal princ,
      const char **languages UNUSED)
{
    char *name = NULL;
    krb5_error_code status;
    char message[BUFSIZ];

    status = krb5_unparse_name(context, princ, &name);
    if (status != 0)
        return status;
    status = pwcheck_check(data, password, name, message, sizeof(message));
    if (status != 0)
        krb5_set_error_message(context, status, "%s", message);
    krb5_free_unparsed_name(context, name);
    return status;
}


/*
 * Shut down the library.
 */
static void
fini(krb5_context context UNUSED, krb5_pwqual_moddata data)
{
    pwcheck_close(data);
}


/*
 * The public symbol that MIT Kerberos looks for.  Builds and returns the
 * vtable.
 */
krb5_error_code
pwqual_strength_initvt(krb5_context context UNUSED, int maj_ver,
                       int min_ver UNUSED, krb5_plugin_vtable vtable)
{
    krb5_pwqual_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_pwqual_vtable)vtable;
    vt->name = "krb5-strength";
    vt->open = init;
    vt->check = check;
    vt->close = fini;
    return 0;
}

#endif /* HAVE_KRB5_PWQUAL_PLUGIN_H */
