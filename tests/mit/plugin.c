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
#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#endif

#include <tests/tap/macros.h>

#ifndef HAVE_KRB5_PWQUAL_PLUGIN_H
/*
 * If we're not building with MIT Kerberos, we can't run this test.  Exit with
 * a special status to communicate this to the test wrapper.
 */
int
main(int argc UNUSED, char *argv[] UNUSED)
{
    exit(42);
}

#else

/* The public symbol that we load and call to get the vtable. */
typedef krb5_error_code pwqual_strength_initvt(krb5_context, int, int,
                                       krb5_plugin_vtable);

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
    krb5_error_code status;
    void *handle;
    krb5_pwqual_moddata data;
    krb5_pwqual_vtable verifier = NULL;
    krb5_error_code (*init)(krb5_context, int, int, krb5_plugin_vtable);

    /* Build the path of the plugin. */
    if (argc != 4) {
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

    /* Load the module and find the correct symbol. */
    handle = dlopen(path, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Cannot dlopen %s: %s\n", path, dlerror());
        exit(1);
    }
    init = dlsym(handle, "pwqual_strength_initvt");
    if (init == NULL) {
        fprintf(stderr, "Cannot get pwqual_strength_initvt symbol: %s\n",
                dlerror());
        exit(1);
    }

    /* Call that function to get the vtable. */
    verifier = malloc(sizeof(*verifier));
    if (verifier == NULL) {
        fprintf(stderr, "Cannot allocate memory: %s\n", strerror(errno));
        exit(1);
    }
    status = init(ctx, 1, 1, (krb5_plugin_vtable) verifier);
    if (status != 0) {
        fprintf(stderr, "Cannot obtain module vtable\n");
        exit(1);
    }
    if (strcmp(verifier->name, "krb5-strength") != 0) {
        fprintf(stderr, "Invalid metadata in plugin\n");
        exit(1);
    }

    /* Open the verifier, run the check function, and close it. */
    status = verifier->open(ctx, argv[3], &data);
    if (status != 0) {
        fprintf(stderr, "%s\n", krb5_get_error_message(ctx, status));
        exit(1);
    }
    status = verifier->check(ctx, data, argv[2], NULL, princ, NULL);
    if (status != 0)
        fprintf(stderr, "%s\n", krb5_get_error_message(ctx, status));
    verifier->close(ctx, data);
    exit(status);
}

#endif /* HAVE_KRB5_PWQUAL_PLUGIN_H */
