/*
 * Test a password for weaknesses using CrackLib.
 *
 * Contained here is the interface from the krb5-strength plugin to the
 * CrackLib library, including initialization and checking of a password
 * against a CrackLib dictionary.
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
#include <portable/system.h>

#include <plugin/internal.h>

/* When using the embedded CrackLib, we need to provide our own prototype. */
#ifdef HAVE_CRACK_H
# include <crack.h>
#else
extern const char *FascistCheck(const char *password, const char *dict);
#endif


/*
 * Initialize the CrackLib dictionary.  Ensure that the dictionary file exists
 * and is readable and store the path in the module context.  Returns 0 on
 * success, non-zero on failure.
 *
 * The dictionary file should not include the trailing .pwd extension.
 * Currently, we don't cope with a NULL dictionary path.
 */
krb5_error_code
strength_init_cracklib(krb5_context ctx, krb5_pwqual_moddata data)
{
    char *file;
    krb5_error_code code;

    /* Sanity-check the dictionary path. */
    if (asprintf(&file, "%s.pwd", data->dictionary) < 0)
        return strength_error_system(ctx, "cannot allocate memory");
    if (access(file, R_OK) != 0) {
        code = strength_error_system(ctx, "cannot read dictionary %s", file);
        free(file);
        return code;
    }
    free(file);
    return 0;
}


/*
 * Check a password against CrackLib.  Returns 0 on success, non-zero on
 * failure or if the password is rejected.
 */
krb5_error_code
strength_check_cracklib(krb5_context ctx, krb5_pwqual_moddata data,
                        const char *password)
{
    const char *result;

    result = FascistCheck(password, data->dictionary);
    if (result != NULL)
        return strength_error_generic(ctx, "%s", result);
    else
        return 0;
}