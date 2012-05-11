/*
 * Test for the MIT Kerberos shared module API.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <dlfcn.h>
#include <errno.h>
#include <krb5.h>

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
 * Expects a principal and a password to check on the command line.  Loads the
 * MIT Kerberos plugin, converts the input into the necessary format, calls
 * the plugin, and reports the results.  Exits with a status matching the
 * return value of the plugin function.
 *
 * We assume that the plugin is available as:
 *
 *     BUILD/../plugin/.libs/passwd_strength.so
 *
 * since we don't want to embed Libtool's libtldl just to run a test.
 */
int
main(int argc, char *argv[])
{
    const char *build;
    char *path;
    size_t length;
    krb5_context ctx;
    krb5_principal princ;
    krb5_data password;
    krb5_error_code status;
    void *handle, *data;
    struct krb5plugin_kadmin_pwcheck_ftable_v0 *verifier;

    /*
     * If we're not building with MIT Kerberos, we can't run this test.  Exit
     * with a special status to communicate this to the test wrapper.
     */
#ifdef HAVE_KRB5_REALM
    exit(42);
#endif

    /* Build the path of the plugin. */
    if (argc != 3) {
        fprintf(stderr, "Wrong number of arguments\n");
        exit(1);
    }
    build = getenv("BUILD");
    if (build == NULL) {
        fprintf(stderr, "No BUILD environment variable set\n");
        exit(1);
    }
    length = strlen(build) + strlen("/../plugin/.libs/passwd_strength.so");
    path = malloc(length + 1);
    if (path == NULL) {
        fprintf(stderr, "Cannot allocate memory: %s\n", strerror(errno));
        exit(1);
    }
    strlcpy(path, build, length + 1);
    strlcat(path, "/../plugin/.libs/passwd_strength.so", length + 1);

    /* Initialize the data structures. */
    status = krb5_init_context(&ctx);
    if (status != 0) {
        fprintf(stderr, "Cannot initialize Kerberos context\n");
        exit(1);
    }
    status = krb5_parse_name(ctx, argv[1], &princ);
    if (status != 0) {
        fprintf(stderr, "Cannot parse principal name\n");
        exit(1);
    }
    password.length = strlen(argv[2]);
    password.data = argv[2];

    /* Load the module and find the correct symbol. */
    handle = dlopen(path, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Cannot dlopen %s: %s\n", path, dlerror());
        exit(1);
    }
    verifier = dlsym(handle, "kadmin_pwcheck_0");
    if (verifier == NULL) {
        fprintf(stderr, "Cannot get kadmin_pwcheck_0 symbol: %s\n", dlerror());
        exit(1);
    }
    if (verifier->minor_version != 0
        || verifier->init == NULL
        || verifier->check == NULL
        || verifier->fini == NULL) {
        fprintf(stderr, "Invalid metadata in plugin\n");
        exit(1);
    }
    status = verifier->init(ctx, &data);
    if (status != 0) {
        fprintf(stderr, "%s\n", krb5_get_error_message(ctx, status));
        exit(1);
    }
    status = verifier->check(ctx, data, princ, &password);
    if (status != 0)
        fprintf(stderr, "%s\n", krb5_get_error_message(ctx, status));
    verifier->fini(ctx, data);
    exit(status);
}
