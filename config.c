/* $Id$
 *
 * isync - IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000-1 Michael R. Elkins <me@mutt.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE 1

#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isync.h"

config_t *boxes = 0;

/* set defaults from the global configuration section */
static void
config_defaults (config_t * conf)
{
    memcpy (conf, &global, sizeof (config_t));
}

#ifndef HAVE_STRNDUP
static char *
strndup (const char *s, size_t nchars)
{
    char *r = malloc (sizeof (char) * (nchars + 1));
    strncpy (r, s, nchars);
    r[nchars] = 0;
    return r;
}
#endif /* ! HAVE_STRNDUP */

char *
expand_strdup (const char *s)
{
    char path[_POSIX_PATH_MAX];
    struct passwd *pw;
    const char *p;

    if (*s == '~')
    {
	s++;
	if (*s == '/')
	{
	    /* current user */
	    pw = getpwuid (getuid ());
	    p = s + 1;
	}
	else
	{
	    char *user;

	    p = strchr (s, '/');
	    if (p)
	    {
		user = strndup (s, (int)(p - s));
		p++;
	    }
	    else
		user = strdup (s);
	    pw = getpwnam (user);
	    free (user);
	}
	if (!pw)
	    return 0;
	snprintf (path, sizeof (path), "%s/%s", pw->pw_dir, p ? p : "");
	s = path;
    }
    else if (*s != '/')
    {
	snprintf (path, sizeof (path), "%s/%s",
		  global.maildir ? global.maildir : "", s);
	s = path;
    }
    return strdup (s);
}

void
load_config (const char *where)
{
    char path[_POSIX_PATH_MAX];
    char buf[1024];
    struct passwd *pw;
    config_t **cur = &boxes;
    int line = 0;
    FILE *fp;
    char *p, *cmd, *val;

    if (!where)
    {
	pw = getpwuid (getuid ());
	snprintf (path, sizeof (path), "%s/.isyncrc", pw->pw_dir);
	where = path;
    }

    printf ("Reading %s\n", where);

    fp = fopen (where, "r");
    if (!fp)
    {
	if (errno != ENOENT)
	    perror ("fopen");
	return;
    }
    buf[sizeof buf - 1] = 0;
    while ((fgets (buf, sizeof (buf) - 1, fp)))
    {
	p = buf;
	cmd = next_arg (&p);
	val = next_arg (&p);
	line++;
	if (!cmd || *cmd == '#')
	    continue;
	if (!strcasecmp ("mailbox", cmd))
	{
	    if (*cur)
		cur = &(*cur)->next;
	    *cur = calloc (1, sizeof (config_t));
	    config_defaults (*cur);
	    /* not expanded at this point */
	    (*cur)->path = strdup (val);
	}
	else if (!strcasecmp ("maildir", cmd))
	{
	    /* this only affects the global setting */
	    free (global.maildir);
	    global.maildir = expand_strdup (val);
	}
	else if (!strcasecmp ("host", cmd))
	{
#if HAVE_LIBSSL
	    if (!strncasecmp ("imaps:", val, 6))
	    {
		val += 6;
		if (*cur)
		{
		    (*cur)->use_imaps = 1;
		    (*cur)->port = 993;
		    (*cur)->use_sslv2 = 1;
		    (*cur)->use_sslv3 = 1;
		}
		else
		{
		    global.use_imaps = 1;
		    global.port = 993;
		    global.use_sslv2 = 1;
		    global.use_sslv3 = 1;
		}
	    }
#endif
	    if (*cur)
		(*cur)->host = strdup (val);
	    else
		global.host = strdup (val);
	}
	else if (!strcasecmp ("user", cmd))
	{
	    if (*cur)
		(*cur)->user = strdup (val);
	    else
		global.user = strdup (val);
	}
	else if (!strcasecmp ("pass", cmd))
	{
	    if (*cur)
		(*cur)->pass = strdup (val);
	    else
		global.pass = strdup (val);
	}
	else if (!strcasecmp ("port", cmd))
	{
	    if (*cur)
		(*cur)->port = atoi (val);
	    else
		global.port = atoi (val);
	}
	else if (!strcasecmp ("box", cmd))
	{
	    if (*cur)
		(*cur)->box = strdup (val);
	    else
		global.box = strdup (val);
	}
	else if (!strcasecmp ("alias", cmd))
	{
	    if (*cur)
		(*cur)->alias = strdup (val);
	}
	else if (!strcasecmp ("maxsize", cmd))
	{
	    if (*cur)
		(*cur)->max_size = atol (val);
	    else
		global.max_size = atol (val);
	}
	else if (!strcasecmp ("MaxMessages", cmd))
	{
	    if (*cur)
		(*cur)->max_messages = atol (val);
	    else
		global.max_messages = atol (val);
	}
	else if (!strcasecmp ("UseNamespace", cmd))
	{
	    if (*cur)
		(*cur)->use_namespace = (strcasecmp (val, "yes") == 0);
	    else
		global.use_namespace = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("CopyDeletedTo", cmd))
	{
	    if (*cur)
		(*cur)->copy_deleted_to = strdup (val);
	    else
		global.copy_deleted_to = strdup (val);
	}
	else if (!strcasecmp ("Expunge", cmd))
	{
	    if (*cur)
		(*cur)->expunge = (strcasecmp (val, "yes") == 0);
	    else
		global.expunge = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("Delete", cmd))
	{
	    if (*cur)
		(*cur)->delete = (strcasecmp (val, "yes") == 0);
	    else
		global.delete = (strcasecmp (val, "yes") == 0);
	}
#if HAVE_LIBSSL
	else if (!strcasecmp ("CertificateFile", cmd))
	{
	    if (*cur)
		(*cur)->cert_file = expand_strdup (val);
	    else
		global.cert_file = expand_strdup (val);
	}
	else if (!strcasecmp ("RequireSSL", cmd))
	{
	    if (*cur)
		(*cur)->require_ssl = (strcasecmp (val, "yes") == 0);
	    else
		global.require_ssl = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("UseSSLv2", cmd))
	{
	    if (*cur)
		(*cur)->use_sslv2 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_sslv2 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("UseSSLv3", cmd))
	{
	    if (*cur)
		(*cur)->use_sslv3 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_sslv3 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("UseTLSv1", cmd))
	{
	    if (*cur)
		(*cur)->use_tlsv1 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_tlsv1 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strcasecmp ("RequireCRAM", cmd))
	{
	    if (*cur)
		(*cur)->require_cram = (strcasecmp (val, "yes") == 0);
	    else
		global.require_cram = (strcasecmp (val, "yes") == 0);
	}
#endif
	else if (buf[0])
	    printf ("%s:%d:unknown keyword:%s\n", path, line, cmd);
    }
    fclose (fp);
}

config_t *
find_box (const char *s)
{
    config_t *p = boxes;

    for (; p; p = p->next)
    {
	if (!strcmp (s, p->path) || (p->alias && !strcmp (s, p->alias)))
	    return p;
	else
	{
	    /* check to see if the full pathname was specified on the
	     * command line.
	     */
	    char *t = expand_strdup (p->path);

	    if (!strcmp (s, t))
	    {
		free (t);
		return p;
	    }
	    free (t);
	}
    }
    return 0;
}
