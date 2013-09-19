/*
 * Test for the Heimdal shared module API.
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

#include <dlfcn.h>
#include <errno.h>

/* kadm5-pwcheck.h isn't always installed by Heimdal. */
#ifdef HAVE_KADM5_PWCHECK_H
# include <kadm5-pwcheck.h>
#else
# define KADM5_PASSWD_VERSION_V1 1

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
#endif /* !HAVE_KADM5_PWCHECK_H */


/*
 * Expects a principal and a password to check on the command line.  Loads the
 * Heimdal plugin, converts the input into the necessary format, calls the
 * plugin, and reports the results.  Exits with a status matching the return
 * value of the plugin function.
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
    void *handle;
    struct kadm5_pw_policy_verifier *verifier;
    int result;
    char error[BUFSIZ] = "";

    /*
     * If we're not building with Heimdal, we can't run this test.  Exit with
     * a special status to communicate this to the test wrapper.
     */
#ifndef HAVE_KRB5_REALM
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
    verifier = dlsym(handle, "kadm5_password_verifier");
    if (verifier == NULL) {
        fprintf(stderr, "Cannot get kadm5_password_verifier symbol: %s\n",
                dlerror());
        exit(1);
    }
    if (strcmp(verifier->name, "krb5-strength") != 0
        || strcmp(verifier->vendor, "Russ Allbery") != 0
        || verifier->version != KADM5_PASSWD_VERSION_V1
        || verifier->funcs == NULL
        || strcmp(verifier->funcs[0].name, "krb5-strength") != 0
        || verifier->funcs[0].func == NULL
        || verifier->funcs[1].name != NULL) {
        fprintf(stderr, "Invalid metadata in plugin\n");
        exit(1);
    }
    result = (verifier->funcs[0].func)(ctx, princ, &password, NULL, error,
                                       sizeof(error));
    if (error[0] != '\0')
        fprintf(stderr, "%s\n", error);
    exit(result);
}
