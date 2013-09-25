/*
 * Test for the MIT Kerberos shared module API.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_KRB5_PWQUAL_PLUGIN_H
# include <krb5/pwqual_plugin.h>
#endif

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>
#include <util/macros.h>

/*
 * The password test data, generated from the JSON source.  Defines an array
 * named cracklib_tests.
 */
#include <tests/data/cracklib.c>


#ifndef HAVE_KRB5_PWQUAL_PLUGIN_H
/*
 * If we're not building with MIT Kerberos, we can't run this test and much of
 * the test won't even compile.  Replace this test with a small program that
 * just calls skip_all.
 */
int
main(void)
{
    skip_all("not built against MIT libraries");
    return 0;
}

#else

/* The public symbol that we load and call to get the vtable. */
typedef krb5_error_code pwqual_strength_initvt(krb5_context, int, int,
                                               krb5_plugin_vtable);


/*
 * Loads the Heimdal password change plugin and tests that its metadata is
 * correct.  Returns a pointer to the kadm5_pw_policy_verifier struct or bails
 * on failure to load the plugin.
 */
static krb5_pwqual_vtable
load_plugin(krb5_context ctx)
{
    char *path;
    void *handle;
    krb5_error_code code;
    krb5_pwqual_vtable vtable = NULL;
    krb5_error_code (*init)(krb5_context, int, int, krb5_plugin_vtable);

    /* Load the module. */
    path = test_file_path("../plugin/.libs/passwd_strength.so");
    if (path == NULL)
        bail("cannot find plugin");
    handle = dlopen(path, RTLD_NOW);
    if (handle == NULL)
        bail("cannot dlopen %s: %s", path, dlerror());
    test_file_path_free(path);

    /* Find the entry point function. */
    init = dlsym(handle, "pwqual_strength_initvt");
    if (init == NULL)
        bail("cannot get pwqual_strength_initvt symbol: %s", dlerror());

    /* Test for correct results when requesting the wrong API version. */
    code = init(ctx, 2, 0, (krb5_plugin_vtable) vtable);
    is_int(code, KRB5_PLUGIN_VER_NOTSUPP,
           "Correct status for bad major API version");

    /* Call that function properly to get the vtable. */
    vtable = bmalloc(sizeof(*vtable));
    code = init(ctx, 1, 1, (krb5_plugin_vtable) vtable);
    if (code != 0)
        bail_krb5(ctx, code, "cannot obtain module vtable");

    /* Check that all of the vtable entries are present. */
    if (vtable->open == NULL || vtable->check == NULL || vtable->close == NULL)
        bail("missing function in module vtable");

    /* Verify the metadata. */
    is_string("krb5-strength", vtable->name, "Module name");

    /* Return the vtable. */
    return vtable;
}


/*
 * Given a Kerberos context, the dispatch table, the module data, and a test
 * case, call out to the password strength checking module and check the
 * results.
 */
static void
is_password_test(krb5_context ctx, const krb5_pwqual_vtable vtable,
                 krb5_pwqual_moddata data, const struct password_test *test)
{
    krb5_principal princ;
    krb5_error_code code;
    const char *error;

    /* Translate the principal into a krb5_principal. */
    code = krb5_parse_name(ctx, test->principal, &princ);
    if (code != 0)
        bail_krb5(ctx, code, "cannot parse principal %s", test->principal);

    /* Call the verifier. */
    code = vtable->check(ctx, data, test->password, NULL, princ, NULL);

    /* Check the results against the test data. */
    is_int(test->code, code, "%s (status)", test->name);
    if (code == 0)
        is_string(test->error, NULL, "%s (error)", test->name);
    else {
        error = krb5_get_error_message(ctx, code);
        is_string(test->error, error, "%s (error)", test->name);
        krb5_free_error_message(ctx, error);
    }

    /* Free the parsed principal. */
    krb5_free_principal(ctx, princ);
}


int
main(void)
{
    char *path, *dictionary, *krb5_config, *krb5_config_empty, *tmpdir;
    char *setup_argv[5];
    const char*build;
    size_t i;
    krb5_context ctx;
    krb5_pwqual_vtable vtable;
    krb5_pwqual_moddata data;
    krb5_error_code code;

    /*
     * Calculate how many tests we have.  There are two tests for the module
     * metadata, three more tests for initializing the plugin, one test for
     * initialization without a valid dictionary, and two tests per password
     * test.  We run all the cracklib tests twice, once with an explicit
     * dictionary path and once from krb5.conf configuration.
     */
    plan(2 + 3 + 2 * ARRAY_SIZE(cracklib_tests) * 2);

    /* Start with the krb5.conf that contains no dictionary configuration. */
    path = test_file_path("data/krb5.conf");
    if (path == NULL)
        bail("cannot find data/krb5.conf in the test suite");
    basprintf(&krb5_config_empty, "KRB5_CONFIG=%s", path);
    putenv(krb5_config_empty);

    /* Obtain a Kerberos context with that krb5.conf file. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Load and initialize the plugin without a dictionary. */
    vtable = load_plugin(ctx);
    code = vtable->open(ctx, NULL, &data);
    is_int(KADM5_MISSING_CONF_PARAMS, code,
           "Plugin initialization (no dictionary)");

    /* Initialize the plugin again with the correct dictionary. */
    build = getenv("BUILD");
    if (build == NULL)
        bail("BUILD not set in the environment");
    basprintf(&dictionary, "%s/data/dictionary", build);
    code = vtable->open(ctx, dictionary, &data);
    is_int(0, code, "Plugin initialization (explicit dictionary)");

    /* Now, run all of the tests. */
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(ctx, vtable, data, &cracklib_tests[i]);

    /* Close that initialization of the plugin and destroy that context. */
    vtable->close(ctx, data);
    krb5_free_context(ctx);
    ctx = NULL;

    /* Set up our krb5.conf with the dictionary configuration. */
    tmpdir = test_tmpdir();
    setup_argv[0] = test_file_path("data/make-krb5-conf");
    if (setup_argv[0] == NULL)
        bail("cannot find data/make-krb5-conf in the test suite");
    setup_argv[1] = dictionary;
    setup_argv[2] = path;
    setup_argv[3] = tmpdir;
    setup_argv[4] = NULL;
    run_setup((const char **) setup_argv);
    test_file_path_free(setup_argv[0]);
    test_file_path_free(path);

    /* Point KRB5_CONFIG at the newly-generated krb5.conf file. */
    basprintf(&krb5_config, "KRB5_CONFIG=%s/krb5.conf", tmpdir);
    putenv(krb5_config);
    free(krb5_config_empty);

    /* Obtain a new Kerberos context with that krb5.conf file. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Run all of the tests again. */
    code = vtable->open(ctx, dictionary, &data);
    is_int(0, code, "Plugin initialization (krb5.conf dictionary)");
    for (i = 0; i < ARRAY_SIZE(cracklib_tests); i++)
        is_password_test(ctx, vtable, data, &cracklib_tests[i]);
    vtable->close(ctx, data);

    /* Manually clean up after the results of make-krb5-conf. */
    basprintf(&path, "%s/krb5.conf", tmpdir);
    unlink(path);
    free(path);
    test_tmpdir_free(tmpdir);

    /* Keep valgrind clean by freeing all memory. */
    free(dictionary);
    krb5_free_context(ctx);
    free(vtable);
    putenv((char *) "KRB5_CONFIG=");
    free(krb5_config);
    return 0;
}

#endif /* HAVE_KRB5_PWQUAL_PLUGIN_H */
