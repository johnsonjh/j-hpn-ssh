/* $OpenBSD: gss-serv-krb5.c,v 1.9 2018/07/09 21:37:55 markus Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI
#ifdef KRB5

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"

#include "ssh-gss.h"

extern Authctxt *the_authctxt;
extern ServerOptions options;

#ifdef HEIMDAL
# include <krb5.h>
#endif
#ifdef HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#elif HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#endif

/* all commands are allowed by default */
char **k5users_allowed_cmds = NULL;

static int ssh_gssapi_k5login_exists();
static int ssh_gssapi_krb5_cmdok(krb5_principal, const char *, const char *,
    int);

static krb5_context krb_context = NULL;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

static int
ssh_gssapi_krb5_init(void)
{
	krb5_error_code problem;

	if (krb_context != NULL)
		return 1;

	problem = krb5_init_context(&krb_context);
	if (problem) {
		logit("Cannot initialize krb5 context");
		return 0;
	}

	return 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

static int
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, char *name)
{
	krb5_principal princ;
	int retval;
	const char *errmsg;
	int k5login_exists;

	if (ssh_gssapi_krb5_init() == 0)
		return 0;

	if ((retval = krb5_parse_name(krb_context, client->exportedname.value,
	    &princ))) {
		errmsg = krb5_get_error_message(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		return 0;
	}
	/* krb5_kuserok() returns 1 if .k5login DNE and this is self-login.
	 * We have to make sure to check .k5users in that case. */
	k5login_exists = ssh_gssapi_k5login_exists();
	/* NOTE: .k5login and .k5users must opened as root, not the user,
	 * because if they are on a krb5-protected filesystem, user credentials
	 * to access these files aren't available yet. */
	if (krb5_kuserok(krb_context, princ, name) && k5login_exists) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (char *)client->displayname.value);
	} else if (ssh_gssapi_krb5_cmdok(princ, client->exportedname.value,
		name, k5login_exists)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s "
		    "(ssh_gssapi_krb5_cmdok)",
		    name, (char *)client->displayname.value);
	} else
		retval = 0;

	krb5_free_principal(krb_context, princ);
	return retval;
}

/* Test for existence of .k5login.
 * We need this as part of our .k5users check, because krb5_kuserok()
 * returns success if .k5login DNE and user is logging in as himself.
 * With .k5login absent and .k5users present, we don't want absence
 * of .k5login to authorize self-login.  (absence of both is required)
 * Returns 1 if .k5login is available, 0 otherwise.
 */
static int
ssh_gssapi_k5login_exists()
{
	char file[MAXPATHLEN];
	struct passwd *pw = the_authctxt->pw;

	snprintf(file, sizeof(file), "%s/.k5login", pw->pw_dir);
	return access(file, F_OK) == 0;
}

/* check .k5users for login or command authorization
 * Returns 1 if principal is authorized, 0 otherwise.
 * If principal is authorized, (global) k5users_allowed_cmds may be populated.
 */
static int
ssh_gssapi_krb5_cmdok(krb5_principal principal, const char *name,
    const char *luser, int k5login_exists)
{
	FILE *fp;
	char file[MAXPATHLEN];
	char *line = NULL;
	char kuser[65]; /* match krb5_kuserok() */
	struct stat st;
	struct passwd *pw = the_authctxt->pw;
	int found_principal = 0;
	int ncommands = 0, allcommands = 0;
	u_long linenum = 0;
	size_t linesize = 0;

	snprintf(file, sizeof(file), "%s/.k5users", pw->pw_dir);
	/* If both .k5login and .k5users DNE, self-login is ok. */
	if (!k5login_exists && (access(file, F_OK) == -1)) {
		return (krb5_aname_to_localname(krb_context, principal,
		    sizeof(kuser), kuser) == 0) &&
		    (strcmp(kuser, luser) == 0);
	}
	if ((fp = fopen(file, "r")) == NULL) {
		int saved_errno = errno;
		/* 2nd access check to ease debugging if file perms are wrong.
		 * But we don't want to report this if .k5users simply DNE. */
		if (access(file, F_OK) == 0) {
			logit("User %s fopen %s failed: %s",
			    pw->pw_name, file, strerror(saved_errno));
		}
		return 0;
	}
	/* .k5users must be owned either by the user or by root */
	if (fstat(fileno(fp), &st) == -1) {
		/* can happen, but very wierd error so report it */
		logit("User %s fstat %s failed: %s",
		    pw->pw_name, file, strerror(errno));
		fclose(fp);
		return 0;
	}
	if (!(st.st_uid == pw->pw_uid || st.st_uid == 0)) {
		logit("User %s %s is not owned by root or user",
		    pw->pw_name, file);
		fclose(fp);
		return 0;
	}
	/* .k5users must be a regular file.  krb5_kuserok() doesn't do this
	  * check, but we don't want to be deficient if they add a check. */
	if (!S_ISREG(st.st_mode)) {
		logit("User %s %s is not a regular file", pw->pw_name, file);
		fclose(fp);
		return 0;
	}
	/* file exists; initialize k5users_allowed_cmds (to none!) */
	k5users_allowed_cmds = xcalloc(++ncommands,
	    sizeof(*k5users_allowed_cmds));

	/* Check each line.  ksu allows unlimited length lines. */
	while (!allcommands && getline(&line, &linesize, fp) != -1) {
		linenum++;
		char *token;

		/* we parse just like ksu, even though we could do better */
		if ((token = strtok(line, " \t\n")) == NULL)
			continue;
		if (strcmp(name, token) == 0) {
			/* we matched on client principal */
			found_principal = 1;
			if ((token = strtok(NULL, " \t\n")) == NULL) {
				/* only shell is allowed */
				k5users_allowed_cmds[ncommands-1] =
				    xstrdup(pw->pw_shell);
				k5users_allowed_cmds =
				    xreallocarray(k5users_allowed_cmds, ++ncommands,
					sizeof(*k5users_allowed_cmds));
				break;
			}
			/* process the allowed commands */
			while (token) {
				if (strcmp(token, "*") == 0) {
					allcommands = 1;
					break;
				}
				k5users_allowed_cmds[ncommands-1] =
				    xstrdup(token);
				k5users_allowed_cmds =
				    xreallocarray(k5users_allowed_cmds, ++ncommands,
					sizeof(*k5users_allowed_cmds));
				token = strtok(NULL, " \t\n");
			}
		}
       }
	free(line);
	if (k5users_allowed_cmds) {
		/* terminate vector */
		k5users_allowed_cmds[ncommands-1] = NULL;
		/* if all commands are allowed, free vector */
		if (allcommands) {
			int i;
			for (i = 0; i < ncommands; i++) {
				free(k5users_allowed_cmds[i]);
			}
			free(k5users_allowed_cmds);
			k5users_allowed_cmds = NULL;
		}
	}
	fclose(fp);
	return found_principal;
}
 

/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

static void
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_code problem;
	krb5_principal princ;
	OM_uint32 maj_status, min_status;
	int len;
	const char *errmsg;

	if (client->creds == NULL) {
		debug("No credentials stored");
		return;
	}

	if (ssh_gssapi_krb5_init() == 0)
		return;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	if ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.prefix,
	    NULL, &ccache)) != 0) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# else
	if ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_text(krb_context, problem));
# endif
		krb5_free_error_message(krb_context, errmsg);
		return;
	}
#else
	if ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		return;
	}
#endif	/* #ifdef HEIMDAL */

	if ((problem = krb5_parse_name(krb_context,
	    client->exportedname.value, &princ))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		return;
	}

	if ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		return;
	}

	krb5_free_principal(krb_context, princ);

	if ((maj_status = gss_krb5_copy_ccache(&min_status,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		return;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = strlen(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#ifdef USE_PAM
	if (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#endif

	krb5_cc_close(krb_context, ccache);

	return;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	NULL,
	&ssh_gssapi_krb5_userok,
	NULL,
	&ssh_gssapi_krb5_storecreds
};

#endif /* KRB5 */

#endif /* GSSAPI */
