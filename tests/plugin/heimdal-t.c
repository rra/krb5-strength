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
#ifdef HAVE_KADM5_KADM5_PWCHECK_H
# include <kadm5/kadm5-pwcheck.h>
#endif

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>
#include <util/macros.h>

/*
 * The password test data, generated from the JSON source.  Defines an arrays
 * named cdb_tests, cracklib_tests, and generic_tests.
 */
#include <tests/data/passwords/cdb.c>
#include <tests/data/passwords/class.c>
#include <tests/data/passwords/cracklib.c>
#include <tests/data/passwords/generic.c>
#include <tests/data/passwords/length.c>


#ifndef HAVE_KADM5_KADM5_PWCHECK_H
/*
 * If we're not building with Heimdal, we can't run this test and much of the
 * test won't even compile.  Replace this test with a small program that just
 * calls skip_all.
 */
int
main(void)
{
    skip_all("not built against Heimdal libraries");
    return 0;
}

#else

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
    path = test_file_path("../plugin/.libs/strength.so");
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
    char *setup_argv[10];
    size_t i, count;
    struct kadm5_pw_policy_verifier *verifier;

    /*
     * Calculate how many tests we have.  There are five tests for the module
     * metadata and two tests per password test.  We run the generic tests
     * twice, once with CrackLib and once with CDB.
     */
    count = ARRAY_SIZE(cracklib_tests);
    count += ARRAY_SIZE(cdb_tests);
    count += ARRAY_SIZE(class_tests);
    count += ARRAY_SIZE(length_tests);
    count += ARRAY_SIZE(generic_tests) * 2;
    plan(5 + count * 2);

    /* Start with the krb5.conf that contains no dictionary configuration. */
    path = test_file_path("data/krb5.conf");
    if (path == NULL)
        bail("cannot find data/krb5.conf in the test suite");
    basprintf(&krb5_config_empty, "KRB5_CONFIG=%s", path);
    putenv(krb5_config_empty);

    /* Load the plugin. */
    verifier = load_plugin();

    /* Set up our krb5.conf with the dictionary configuration. */
    setup_argv[0] = test_file_path("data/make-krb5-conf");
    if (setup_argv[0] == NULL)
        bail("cannot find data/make-krb5-conf in the test suite");
    tmpdir = test_tmpdir();
    setup_argv[1] = path;
    setup_argv[2] = tmpdir;
    setup_argv[3] = (char *) "password_dictionary";
    basprintf(&setup_argv[4], "%s/data/dictionary", getenv("BUILD"));
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Point KRB5_CONFIG at the newly-generated krb5.conf file. */
    basprintf(&krb5_config, "KRB5_CONFIG=%s/krb5.conf", tmpdir);
    putenv(krb5_config);
    free(krb5_config_empty);

    /* Now, run all of the tests. */
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(verifier, &cracklib_tests[i]);
    for (i = 0; i < ARRAY_SIZE(generic_tests); i++)
        is_password_test(verifier, &generic_tests[i]);

    /* Add character class restrictions. */
    setup_argv[5] = (char *) "require_ascii_printable";
    setup_argv[6] = (char *) "true";
    setup_argv[7] = (char *) "require_non_letter";
    setup_argv[8] = (char *) "true";
    setup_argv[9] = NULL;
    run_setup((const char **) setup_argv);

    /* Run the character class tests. */
    for (i = 0; i < ARRAY_SIZE(class_tests); i++)
        is_password_test(verifier, &class_tests[i]);

    /*
     * Add length restrictions and remove the dictionary.  This should only do
     * length checks without any dictionary checks.
     */
    free(setup_argv[4]);
    setup_argv[3] = (char *) "minimum_length";
    setup_argv[4] = (char *) "12";
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);

    /* Run the length tests. */
    for (i = 0; i < ARRAY_SIZE(length_tests); i++)
        is_password_test(verifier, &length_tests[i]);

#ifdef HAVE_CDB

    /* If built with CDB, set up krb5.conf to use a CDB dictionary instead. */
    setup_argv[3] = (char *) "password_dictionary_cdb";
    setup_argv[4] = test_file_path("data/wordlist.cdb");
    if (setup_argv[4] == NULL)
        bail("cannot find data/wordlist.cdb in the test suite");
    setup_argv[5] = NULL;
    run_setup((const char **) setup_argv);
    test_file_path_free(setup_argv[0]);
    test_file_path_free(setup_argv[4]);
    test_file_path_free(path);

    /* Run the CDB tests. */
    for (i = 0; i < ARRAY_SIZE(cdb_tests); i++)
        is_password_test(verifier, &cdb_tests[i]);
    for (i = 0; i < ARRAY_SIZE(generic_tests); i++)
        is_password_test(verifier, &generic_tests[i]);

#else /* !HAVE_CDB */

    /* Otherwise, mark the CDB tests as skipped. */
    count = ARRAY_SIZE(cdb_tests) + ARRAY_SIZE(generic_tests);
    skip_block(count * 2, "not built with CDB support");

#endif /* !HAVE_CDB */

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

#endif /* HAVE_KADM5_KADM5_PWCHECK_H */
