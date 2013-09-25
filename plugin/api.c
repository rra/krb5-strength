/*
 * The public APIs of the password strength checking kadmind plugin.
 *
 * Provides the public pwcheck_init, pwcheck_check, and pwcheck_close APIs for
 * the kadmind plugin.
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
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>
#include <errno.h>

#include <plugin/api.h>

/* Heimdal doesn't define KADM5_PASS_Q_GENERIC. */
#ifndef KADM5_PASS_Q_GENERIC
# define KADM5_PASS_Q_GENERIC KADM5_PASS_Q_DICT
#endif

/*
 * Used to store local state.  Currently, all we have is the dictionary path,
 * which we get from kadmind rather than from krb5.conf since it's already a
 * kdc.conf setting.
 */
struct context {
    char *dictionary;
};

/* The public function exported by the cracklib library. */
extern char *FascistCheck(const char *password, const char *dict);


/*
 * Initialize the module.  Ensure that the dictionary file exists and is
 * readable and store the path in the module context.  Returns 0 on success,
 * non-zero on failure.  This function returns failure only if it could not
 * allocate memory.
 *
 * The dictionary file should not include the trailing .pwd extension.
 * Currently, we don't cope with a NULL dictionary path.
 */
krb5_error_code
pwcheck_init(void **context, const char *dictionary)
{
    char *path;
    size_t length;
    struct context *ctx;

    if (dictionary == NULL)
        return KADM5_MISSING_CONF_PARAMS;
    length = strlen(dictionary) + strlen(".pwd") + 1;
    path = malloc(length);
    if (path == NULL)
        return errno;
    snprintf(path, length, "%s.pwd", dictionary);
    if (access(path, R_OK) != 0)
        return errno;
    path[strlen(path) - strlen(".pwd")] = '\0';
    ctx = malloc(sizeof(struct context));
    if (ctx == NULL)
        return errno;
    ctx->dictionary = path;
    *context = ctx;
    return 0;
}


/*
 * Check a given password.  Takes our local context, the password, the
 * principal the password is for, and a buffer and buffer length into which to
 * put any failure message.
 */
krb5_error_code
pwcheck_check(void *context, const char *password, const char *principal,
              char *errstr, int errstrlen)
{
    char *user, *p;
    const char *q;
    size_t i, j;
    char c;
    int err;
    const char *result;
    struct context *ctx = context;

    /*
     * We get the principal (in krb5_unparse_name format) from kadmind and we
     * want to be sure that the password doesn't match the username, the
     * username reversed, or the username with trailing digits.  We therefore
     * have to copy the string so that we can manipulate it a bit.
     */
    if (strcasecmp(password, principal) == 0) {
        snprintf(errstr, errstrlen, "Password based on username");
        return KADM5_PASS_Q_GENERIC;
    }
    user = strdup(principal);
    if (user == NULL) {
        err = errno;
        snprintf(errstr, errstrlen, "Cannot allocate memory");
        return err;
    }
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
    if (strlen(password) == strlen(user)) {
        if (strcasecmp(password, user) == 0) {
            free(user);
            snprintf(errstr, errstrlen, "Password based on username");
            return KADM5_PASS_Q_GENERIC;
        }

        /* Check against the reversed username. */
        for (i = 0, j = strlen(user) - 1; i < j; i++, j--) {
            c = user[i];
            user[i] = user[j];
            user[j] = c;
        }
        if (strcasecmp(password, user) == 0) {
            free(user);
            snprintf(errstr, errstrlen, "Password based on username");
            return KADM5_PASS_Q_GENERIC;
        }
    }
    if (strlen(password) > strlen(user))
        if (strncasecmp(password, user, strlen(user)) == 0) {
            q = password + strlen(user);
            while (isdigit((int) *q))
                q++;
            if (*q == '\0') {
                free(user);
                snprintf(errstr, errstrlen, "Password based on username");
                return KADM5_PASS_Q_GENERIC;
            }
        }
    free(user);
    result = FascistCheck(password, ctx->dictionary);
    if (result != NULL) {
        strlcpy(errstr, result, errstrlen);
        return KADM5_PASS_Q_GENERIC;
    }
    return 0;
}


/*
 * Cleanly shut down the password strength plugin.  The only thing we have to
 * do is free our context memory.
 */
void
pwcheck_close(void *context)
{
    struct context *ctx = context;

    if (ctx != NULL) {
        if (ctx->dictionary != NULL)
            free(ctx->dictionary);
        free(ctx);
    }
}
