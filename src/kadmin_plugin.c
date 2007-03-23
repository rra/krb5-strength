/* cc -dynamiclib -o plugin.so ~/plugin.c -lcrack */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

extern char * FascistCheck(char *passwd,char *dictpath) ; 

static struct lctx {
    char *dict_file;
} l_context;

int pwcheck_init(void **context, const char *dict_file)
{
    static char p[PATH_MAX];
    static struct stat st;

    strncpy(p, dict_file, PATH_MAX-5);
    strncat(p, ".pwd", PATH_MAX);
    p[PATH_MAX - 1] = '\0';
    
    if (lstat(p, &st) < 0)
	return 1;

    *context = &l_context;

    l_context.dict_file = strdup(dict_file);
    
    return 0;
}

int pwcheck_check(void *context, const char *password, const char
		  *princ, char *msg, int msglen)
{
    char *msg2;

    if (msg2 = FascistCheck((char *)password, ((struct lctx *)context)->dict_file))
    {
	strncpy(msg, msg2, msglen);
	msg[msglen - 1] = '\0';
	return 1;
    }
    
    if (strcasecmp(password, princ) == 0) {
	snprintf(msg, msglen, "You can't use \"%s\" as a password!",
		 princ);
	msg[msglen - 1] = '\0';
	return 1;
    }

    return 0;
}

void pwcheck_close(void *context)
{
    if (l_context.dict_file) free(l_context.dict_file);
    l_context.dict_file = NULL;
}
