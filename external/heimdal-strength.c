/*
 * Password strength checking program for Heimdal.
 *
 * This is a wrapper around the krb5-strength-modified version of CrackLib
 * that supports the Heimdal external password strength check program
 * interface.  It uses a krb5.conf parameter to determine the location of its
 * dictionary.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2009, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>

#include <plugin/api.h>
#include <util/macros.h>
#include <util/messages.h>
#include <util/xmalloc.h>


/*
 * Heimdal and MIT use different structures for the realm.  This doesn't
 * really need to build on MIT, but may as well.
 */
#ifdef HAVE_KRB5_REALM
static void
free_realm(krb5_realm *realm_data)
{
    if (*realm_data != NULL) {
        free(*realm_data);
        *realm_data = NULL;
    }
}

static void
set_realm(krb5_realm *realm_data, const char *realm)
{
    free_realm(realm_data);
    *realm_data = xstrdup(realm);
}

#else /* !HAVE_KRB5_REALM */

static void
free_realm(krb5_data **realm_data)
{
    if (*realm_data != NULL) {
        if ((*realm_data)->data != NULL)
            free((*realm_data)->data);
        free(*realm_data);
        *realm_data = NULL;
    }
}

static void
set_realm(krb5_data **realm_data, const char *realm)
{
    free_realm(realm_data);
    *realm_data = xmalloc(sizeof(**realm_data));
    (*realm_data)->data = xstrdup(realm);
    (*realm_data)->magic = KV5M_DATA;
    (*realm_data)->length = strlen(realm);
}

#endif /* !HAVE_KRB5_REALM */


/*
 * Initialize the password strength checking functions and returns the context
 * handle for the strength checking plugin.  Exits on failure.
 */
static void *
initialize(void)
{
    void *context;
    krb5_context ctx;
    char *realm = NULL;
    char *dictionary = NULL;
#ifdef HAVE_KRB5_REALM
    krb5_realm realm_data = NULL;
#else
    krb5_data *realm_data = NULL;
#endif

    /* We need to create a Kerberos context just to get the dictionary path. */
    if (krb5_init_context(&ctx) != 0)
        die("Cannot create Kerberos context");
    krb5_get_default_realm(ctx, &realm);
    if (realm != NULL)
        set_realm(&realm_data, realm);
    krb5_appdefault_string(ctx, "krb5-strength", realm_data,
                           "password_dictionary", "", &dictionary);
    if (dictionary == NULL || dictionary[0] == '\0')
        die("password_dictionary not configured in krb5.conf");
    if (realm != NULL) {
        krb5_free_default_realm(ctx, realm);
        free_realm(&realm_data);
    }
    if (pwcheck_init(&context, dictionary) != 0)
        sysdie("Cannot initialize strength checking");
    free(dictionary);
    return context;
}


/*
 * Read a key/value pair from stdin, check that the key is the one expected,
 * and if so, copy the value into the provided buffer.  Exits with an
 * appropriate error on failure.
 */
static void
read_key(const char *key, char *buffer, size_t length)
{
    char *p;

    if (fgets(buffer, length, stdin) == NULL)
        sysdie("Cannot read %s", key);
    if (strlen(buffer) < 1 || buffer[strlen(buffer) - 1] != '\n')
        die("Malformed or too long %s line", key);
    buffer[strlen(buffer) - 1] = '\0';
    if (strncmp(buffer, key, strlen(key)) != 0)
        die("Malformed %s line", key);
    p = buffer + strlen(key);
    if (p[0] != ':' || p[1] != ' ')
        die("Malformed %s line", key);
    p += 2;
    memmove(buffer, p, strlen(p) + 1);
}


/*
 * Read a principal and password from standard input and do strength checking
 * on that principal and password, returning the results expected by the
 * Heimdal external-check interface.  Takes the password strength checking
 * context.
 */
static void
check_password(void *context)
{
    char principal[BUFSIZ], password[BUFSIZ], error[BUFSIZ], end[BUFSIZ];

    read_key("principal", principal, sizeof(principal));
    read_key("new-password", password, sizeof(password));
    if (fgets(end, sizeof(end), stdin) == NULL)
        sysdie("Cannot read end of entry");
    if (strcmp(end, "end\n") != 0)
        die("Malformed end line");
    if (pwcheck_check(context, password, principal, error, sizeof(error)))
        fprintf(stderr, "%s\n", error);
    else
        printf("APPROVED\n");
}


/*
 * Main routine.  There will be one argument, the principal, but we ignore it
 * (we get it again via the input data).
 *
 * Heimdal 1.3 appears to pass the principal as argv[0], where the name of the
 * program would normally be, so allow for that behavior as well.
 */
int
main(int argc, char *argv[] UNUSED)
{
    void *context;

    if (argc != 1 && argc != 2)
        die("Usage: heimdal-strength <principal>");
    context = initialize();
    check_password(context);
    exit(0);
}
