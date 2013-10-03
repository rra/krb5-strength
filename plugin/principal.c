/*
 * Password strength checks based on the principal.
 *
 * Performs various checks of the password against the principal for which the
 * password is being changed, trying to detect and reject passwords based on
 * components of the principal.
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

#include <ctype.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Check whether the password is based in some way on the principal.  Returns
 * 0 if it is not and some non-zero error code if it appears to be.
 */
krb5_error_code
strength_check_principal(krb5_context ctx, krb5_pwqual_moddata data UNUSED,
                         const char *principal, const char *password)
{
    char *user, *p;
    const char *q;
    size_t i, j;
    char c;

    /*
     * We get the principal (in krb5_unparse_name format) and we want to be
     * sure that the password doesn't match the username, the username
     * reversed, or the username with trailing digits.  We therefore have to
     * copy the string so that we can manipulate it a bit.
     */
    if (strcasecmp(password, principal) == 0)
        return strength_error_generic(ctx, ERROR_USERNAME);
    user = strdup(principal);
    if (user == NULL)
        return strength_error_system(ctx, "cannot allocate memory");

    /* Strip the realm off of the principal. */
    for (p = user; p[0] != '\0'; p++) {
        if (p[0] == '\\' && p[1] != '\0') {
            p++;
            continue;
        }
        if (p[0] == '@') {
            p[0] = '\0';
            break;
        }
    }

    /*
     * If the length of the password matches the length of the local portion
     * of the principal, check for exact matches or reversed matches.
     */
    if (strlen(password) == strlen(user)) {
        if (strcasecmp(password, user) == 0) {
            free(user);
            return strength_error_generic(ctx, ERROR_USERNAME);
        }

        /* Check against the reversed username. */
        for (i = 0, j = strlen(user) - 1; i < j; i++, j--) {
            c = user[i];
            user[i] = user[j];
            user[j] = c;
        }
        if (strcasecmp(password, user) == 0) {
            free(user);
            return strength_error_generic(ctx, ERROR_USERNAME);
        }
    }

    /*
     * If the length is greater, check whether the user just added trailing
     * digits to the local portion of the principal to form the password.
     */
    if (strlen(password) > strlen(user))
        if (strncasecmp(password, user, strlen(user)) == 0) {
            q = password + strlen(user);
            while (isdigit((unsigned char) *q))
                q++;
            if (*q == '\0') {
                free(user);
                return strength_error_generic(ctx, ERROR_USERNAME);
            }
        }

    /* Password does not appear to be based on the principal. */
    free(user);
    return 0;
}
