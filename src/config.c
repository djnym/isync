/* $Id$
 *
 * isync - IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000-2 Michael R. Elkins <me@mutt.org>
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
 * 
 * As a special exception, isync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

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

static char *
my_strndup (const char *s, size_t nchars)
{
    char *r = malloc (sizeof (char) * (nchars + 1));
    strncpy (r, s, nchars);
    r[nchars] = 0;
    return r;
}

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
		user = my_strndup (s, (int)(p - s));
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

static int
is_true (const char *val)
{
    return
	!strcasecmp (val, "yes") ||
	!strcasecmp (val, "true") ||
	!strcasecmp (val, "on") ||
	!strcmp (val, "1");
}

void
load_config (const char *where, int *o2o)
{
    char path[_POSIX_PATH_MAX];
    char buf[1024];
    struct passwd *pw;
    config_t **stor = &boxes, *cfg;
    int line = 0;
    FILE *fp;
    char *p, *cmd, *val;

    if (!where)
    {
	pw = getpwuid (getuid ());
	snprintf (path, sizeof (path), "%s/.isyncrc", pw->pw_dir);
	where = path;
    }

    info ("Reading configuration file %s\n", where);

    fp = fopen (where, "r");
    if (!fp)
    {
	if (errno != ENOENT)
	    perror ("fopen");
	return;
    }
    buf[sizeof buf - 1] = 0;
    cfg = &global;
    while ((fgets (buf, sizeof (buf) - 1, fp)))
    {
	p = buf;
	cmd = next_arg (&p);
	val = next_arg (&p);
	line++;
	if (!cmd || *cmd == '#')
	    continue;
	if (!val) {
	    fprintf (stderr, "%s:%d: parameter missing\n", path, line);
	    continue;
	}
	if (!strcasecmp ("mailbox", cmd))
	{
	    if (*o2o)
		break;
	    cfg = *stor = malloc (sizeof (config_t));
	    stor = &cfg->next;
	    config_defaults (cfg);
	    /* not expanded at this point */
	    cfg->path = strdup (val);
	}
	else if (!strcasecmp ("OneToOne", cmd))
	{
	    if (boxes) {
	      forbid:
		fprintf (stderr,
			 "%s:%d: keyword '%s' allowed only in global section\n",
			 path, line, cmd);
		continue;
	    }
	    *o2o = is_true (val);
	}
	else if (!strcasecmp ("maildir", cmd))
	{
	    if (boxes)
		goto forbid;
	    /* this only affects the global setting */
	    free (global.maildir);
	    global.maildir = expand_strdup (val);
	}
	else if (!strcasecmp ("folder", cmd))
	{
	    if (boxes)
		goto forbid;
	    /* this only affects the global setting */
	    global.folder = strdup (val);
	}
	else if (!strcasecmp ("inbox", cmd))
	{
	    if (boxes)
		goto forbid;
	    /* this only affects the global setting */
	    global.inbox = strdup (val);
	}
	else if (!strcasecmp ("host", cmd))
	{
#if HAVE_LIBSSL
	    if (!strncasecmp ("imaps:", val, 6))
	    {
		val += 6;
		cfg->use_imaps = 1;
		cfg->port = 993;
		cfg->use_sslv2 = 1;
		cfg->use_sslv3 = 1;
	    }
#endif
	    cfg->host = strdup (val);
	}
	else if (!strcasecmp ("user", cmd))
	{
	    if (boxes)
		cfg->user = strdup (val);
	    else {
		free (global.user);
		global.user = strdup (val);
	    }
	}
	else if (!strcasecmp ("pass", cmd))
	    cfg->pass = strdup (val);
	else if (!strcasecmp ("port", cmd))
	    cfg->port = atoi (val);
	else if (!strcasecmp ("box", cmd))
	    cfg->box = strdup (val);
	else if (!strcasecmp ("alias", cmd))
	{
	    if (!boxes) {
		fprintf (stderr,
			 "%s:%d: keyword 'alias' allowed only in mailbox specification\n",
			 path, line);
		continue;
	    }
	    cfg->alias = strdup (val);
	}
	else if (!strcasecmp ("maxsize", cmd))
	    cfg->max_size = atol (val);
	else if (!strcasecmp ("MaxMessages", cmd))
	    cfg->max_messages = atol (val);
	else if (!strcasecmp ("UseNamespace", cmd))
	    cfg->use_namespace = is_true (val);
	else if (!strcasecmp ("CopyDeletedTo", cmd))
	    cfg->copy_deleted_to = strdup (val);
	else if (!strcasecmp ("Tunnel", cmd))
	    cfg->tunnel = strdup (val);
	else if (!strcasecmp ("Expunge", cmd))
	    cfg->expunge = is_true (val);
	else if (!strcasecmp ("Delete", cmd))
	    cfg->delete = is_true (val);
#if HAVE_LIBSSL
	else if (!strcasecmp ("CertificateFile", cmd))
	    cfg->cert_file = expand_strdup (val);
	else if (!strcasecmp ("RequireSSL", cmd))
	    cfg->require_ssl = is_true (val);
	else if (!strcasecmp ("UseSSLv2", cmd))
	    cfg->use_sslv2 = is_true (val);
	else if (!strcasecmp ("UseSSLv3", cmd))
	    cfg->use_sslv3 = is_true (val);
	else if (!strcasecmp ("UseTLSv1", cmd))
	    cfg->use_tlsv1 = is_true (val);
	else if (!strcasecmp ("RequireCRAM", cmd))
	    cfg->require_cram = is_true (val);
#endif
	else if (buf[0])
	    fprintf (stderr, "%s:%d: unknown keyword '%s'\n", path, line, cmd);
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

void
free_config (void)
{
    free (global.user);
    free (global.maildir);
    free (global.host);
    free (global.pass);
}
