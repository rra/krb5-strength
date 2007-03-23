/*
 * api.c
 *
 * The public APIs of the password strength checking kadmind plugin.
 *
 * Provides the public pwcheck_init, pwcheck_check, and pwcheck_close APIs for
 * the kadmind plugin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
int
pwcheck_init(void **context, const char *dictionary)
{
    char *path;
    size_t length;
    struct context *ctx;

    if (dictionary == NULL)
        return 1;
    length = strlen(dictionary) + strlen(".pwd") + 1;
    path = malloc(length);
    if (path == NULL)
        return 1;
    snprintf(path, length, "%s.pwd", dictionary);
    if (access(path, R_OK) != 0)
        return 1;
    path[strlen(path) - strlen(".pwd")] = '\0';
    ctx = malloc(sizeof(struct context));
    if (ctx == NULL)
        return 1;
    ctx->dictionary = path;
    *context = ctx;
    return 0;
}


/*
 * Check a given password.  Takes our local context, the password, the
 * principal the password is for, and a buffer and buffer length into which to
 * put any failure message.
 */
int
pwcheck_check(void *context, const char *password, const char *principal,
              char *errstr, int errstrlen)
{
    const char *result;
    struct context *ctx = context;

    if (strcasecmp(password, principal) == 0) {
	snprintf(errstr, errstrlen, "Password same as username");
        errstr[errstrlen - 1] = '\0';
	return 1;
    }
    result = FascistCheck(password, ctx->dictionary);
    if (result != NULL) {
        strncpy(errstr, result, errstrlen);
        errstr[errstrlen - 1] = '\0';
        return 1;
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
