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

#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include "isync.h"

static config_t *box = 0;

/* set defaults from the global configuration section */
void
config_defaults (config_t * conf)
{
    conf->user = global.user;
    conf->pass = global.pass;
    conf->port = global.port;
    conf->box = global.box;
    conf->host = global.host;
    conf->max_size = global.max_size;
    conf->copy_deleted_to = global.copy_deleted_to;
    conf->use_namespace = global.use_namespace;
    conf->expunge = global.expunge;
#if HAVE_LIBSSL
    conf->require_ssl = global.require_ssl;
    conf->use_imaps = global.use_imaps;
    conf->cert_file = global.cert_file;
    conf->use_sslv2 = global.use_sslv2;
    conf->use_sslv3 = global.use_sslv3;
    conf->use_tlsv1 = global.use_tlsv1;
#endif
}

/* `s' is destroyed by this call */
static char *
expand_strdup (char *s)
{
    char path[_POSIX_PATH_MAX];
    struct passwd *pw;
    char *p;

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
	    p = strchr (s, '/');
	    if (p)
		*p++ = 0;
	    pw = getpwnam (s);
	}
	if (!pw)
	    return 0;
	snprintf (path, sizeof (path), "%s/%s", pw->pw_dir, p ? p : "");
	s = path;
    }
    else if (*s != '/')
    {
	snprintf (path, sizeof (path), "%s/%s", global.maildir, s);
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
    config_t **cur = &box;
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
	if (!strncasecmp ("mailbox", cmd, 7))
	{
	    if (*cur)
		cur = &(*cur)->next;
	    *cur = calloc (1, sizeof (config_t));
	    config_defaults (*cur);
	    (*cur)->path = expand_strdup (val);
	}
	else if (!strncasecmp ("maildir", cmd, 7))
	{
	    /* this only affects the global setting */
	    free (global.maildir);
	    global.maildir = expand_strdup (val);
	}
	else if (!strncasecmp ("host", cmd, 4))
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
	else if (!strncasecmp ("user", cmd, 4))
	{
	    if (*cur)
		(*cur)->user = strdup (val);
	    else
		global.user = strdup (val);
	}
	else if (!strncasecmp ("pass", cmd, 4))
	{
	    if (*cur)
		(*cur)->pass = strdup (val);
	    else
		global.pass = strdup (val);
	}
	else if (!strncasecmp ("port", cmd, 4))
	{
	    if (*cur)
		(*cur)->port = atoi (val);
	    else
		global.port = atoi (val);
	}
	else if (!strncasecmp ("box", cmd, 3))
	{
	    if (*cur)
		(*cur)->box = strdup (val);
	    else
		global.box = strdup (val);
	}
	else if (!strncasecmp ("alias", cmd, 5))
	{
	    if (*cur)
		(*cur)->alias = strdup (val);
	}
	else if (!strncasecmp ("maxsize", cmd, 7))
	{
	    if (*cur)
		(*cur)->max_size = atol (val);
	    else
		global.max_size = atol (val);
	}
	else if (!strncasecmp ("UseNamespace", cmd, 12))
	{
	    if (*cur)
		(*cur)->use_namespace = (strcasecmp (val, "yes") == 0);
	    else
		global.use_namespace = (strcasecmp (val, "yes") == 0);
	}
	else if (!strncasecmp ("CopyDeletedTo", cmd, 13))
	{
	    if (*cur)
		(*cur)->copy_deleted_to = strdup (val);
	    else
		global.copy_deleted_to = strdup (val);
	}
	else if (!strncasecmp ("Expunge", cmd, 7))
	{
	    if (*cur)
		(*cur)->expunge = (strcasecmp (val, "yes") == 0);
	    else
		global.expunge = (strcasecmp (val, "yes") == 0);
	}
#if HAVE_LIBSSL
	else if (!strncasecmp ("CertificateFile", cmd, 15))
	{
	    if (*cur)
		(*cur)->cert_file = expand_strdup (val);
	    else
		global.cert_file = expand_strdup (val);
	}
	else if (!strncasecmp ("RequireSSL", cmd, 10))
	{
	    if (*cur)
		(*cur)->require_ssl = (strcasecmp (val, "yes") == 0);
	    else
		global.require_ssl = (strcasecmp (val, "yes") == 0);
	}
	else if (!strncasecmp ("UseSSLv2", cmd, 8))
	{
	    if (*cur)
		(*cur)->use_sslv2 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_sslv2 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strncasecmp ("UseSSLv3", cmd, 8))
	{
	    if (*cur)
		(*cur)->use_sslv3 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_sslv3 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strncasecmp ("UseTLSv1", cmd, 8))
	{
	    if (*cur)
		(*cur)->use_tlsv1 = (strcasecmp (val, "yes") == 0);
	    else
		global.use_tlsv1 = (strcasecmp (val, "yes") == 0);
	}
	else if (!strncasecmp ("RequireCRAM", cmd, 11))
	{
	    if (*cur)
		(*cur)->require_cram = (strcasecmp (val, "yes") == 0);
	    else
		global.require_cram = (strcasecmp (val, "yes") == 0);
	}
#endif
	else if (buf[0])
	    printf ("%s:%d:unknown command:%s", path, line, cmd);
    }
    fclose (fp);
}

config_t *
find_box (const char *s)
{
    config_t *p = box;

    for (; p; p = p->next)
	if (!strcmp (s, p->path) || (p->alias && !strcmp (s, p->alias)))
	    return p;
    return 0;
}
