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

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>
#include <util/macros.h>

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
 * The password test data, generated from the JSON source.  Defines an array
 * named cracklib_tests.
 */
#include <tests/data/cracklib.c>


/*
 * Loads the Heimdal password change plugin and tests that its metadata is
 * correct.  Returns a pointer to the kadm5_pw_policy_verifier struct or bails
 * on failure to load the plugin.
 */
static struct kadm5_pw_policy_verifier *
load_plugin(void)
{
    char *path;
    void *handle;
    struct kadm5_pw_policy_verifier *verifier;

    /* Load the module. */
    path = test_file_path("../plugin/.libs/passwd_strength.so");
    if (path == NULL)
        bail("cannot find plugin");
    handle = dlopen(path, RTLD_NOW);
    if (handle == NULL)
        sysbail("cannot dlopen %s: %s", path, dlerror());
    test_file_path_free(path);

    /* Find the dispatch table and do a basic sanity check. */
    verifier = dlsym(handle, "kadm5_password_verifier");
    if (verifier == NULL)
        sysbail("cannot get kadm5_password_verifier symbol: %s", dlerror());
    if (verifier->funcs == NULL || verifier->funcs[0].func == NULL)
        bail("no verifier functions in module");

    /* Verify the metadata. */
    is_string("krb5-strength", verifier->name, "Module name");
    is_string("Russ Allbery", verifier->vendor, "Module vendor");
    is_int(KADM5_PASSWD_VERSION_V1, verifier->version, "Module version");
    is_string("krb5-strength", verifier->funcs[0].name,
              "Module function name");
    ok(verifier->funcs[1].name == NULL, "Only one function in module");

    /* Return the dispatch table. */
    return verifier;
}


/*
 * Given the dispatch table and a test case, call out to the password strength
 * checking module and check the results.
 */
static void
is_password_test(const struct kadm5_pw_policy_verifier *verifier,
                 const struct password_test *test)
{
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    krb5_data password;
    int result;
    char error[BUFSIZ] = "";

    /* Obtain a Kerberos context to use for parsing principal names. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Translate the test data into the form that the verifier expects. */
    code = krb5_parse_name(ctx, test->principal, &princ);
    if (code != 0)
        bail_krb5(ctx, code, "cannot parse principal %s", test->principal);
    password.data = (char *) test->password;
    password.length = strlen(test->password);

    /* Call the verifier. */
    result = (verifier->funcs[0].func)(ctx, princ, &password, NULL, error,
                                       sizeof(error));

    /* Heimdal only returns 0 or 1, so translate the expected code. */
    is_int(test->code == 0 ? 0 : 1, result, "%s (status)", test->name);
    is_string(test->error == NULL ? "" : test->error, error, "%s (error)",
              test->name);

    /* Free data structures. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
}


int
main(void)
{
    char *path, *krb5_config, *krb5_config_empty, *tmpdir;
    char *setup_argv[5];
    size_t i;
    struct kadm5_pw_policy_verifier *verifier;
    struct password_test no_dictionary_test = {
        "no dictionary configured",
        "test@EXAMPLE.ORG",
        "password",
        1,
        "cannot initialize strength checking",
    };

    /* If we're not building with Heimdal, we can't run this test. */
#ifndef HAVE_KRB5_REALM
    skip_all("not built against Heimdal libraries");
#endif

    /*
     * Calculate how many tests we have.  There are five tests for the module
     * metadata, one more password test than the list of password tests we
     * have configured, and two tests per password test.
     */
    plan(5 + (ARRAY_SIZE(cracklib_tests) + 1) * 2);

    /* Start with the krb5.conf that contains no dictionary configuration. */
    path = test_file_path("data/krb5.conf");
    if (path == NULL)
        bail("cannot find data/krb5.conf in the test suite");
    basprintf(&krb5_config_empty, "KRB5_CONFIG=%s", path);
    putenv(krb5_config_empty);

    /* Load the plugin. */
    verifier = load_plugin();

    /* Try an initial password verification with no dictionary configured. */
    is_password_test(verifier, &no_dictionary_test);

    /* Set up our krb5.conf with the dictionary configuration. */
    setup_argv[0] = test_file_path("data/make-krb5-conf");
    if (setup_argv[0] == NULL)
        bail("cannot find data/make-krb5-conf in the test suite");
    basprintf(&setup_argv[1], "%s/data/dictionary", getenv("BUILD"));
    tmpdir = test_tmpdir();
    setup_argv[2] = path;
    setup_argv[3] = tmpdir;
    setup_argv[4] = NULL;
    run_setup((const char **) setup_argv);
    test_file_path_free(setup_argv[0]);
    free(setup_argv[1]);
    test_file_path_free(path);

    /* Point KRB5_CONFIG at the newly-generated krb5.conf file. */
    basprintf(&krb5_config, "KRB5_CONFIG=%s/krb5.conf", tmpdir);
    putenv(krb5_config);
    free(krb5_config_empty);

    /* Now, run all of the tests. */
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(verifier, &cracklib_tests[i]);

    /* Manually clean up after the results of make-krb5-conf. */
    basprintf(&path, "%s/krb5.conf", tmpdir);
    unlink(path);
    free(path);
    test_tmpdir_free(tmpdir);

    /* Keep valgrind clean by freeing environmental memory. */
    putenv((char *) "KRB5_CONFIG=");
    free(krb5_config);
    return 0;
}
