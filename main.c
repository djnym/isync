/* $Id$
 *
 * isync - IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000 Michael R. Elkins <me@mutt.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "isync.h"

#if HAVE_GETOPT_LONG
#define _GNU_SOURCE
#include <getopt.h>

struct option Opts[] = {
    {"config", 1, NULL, 'c'},
    {"delete", 0, NULL, 'd'},
    {"expunge", 0, NULL, 'e'},
    {"fast", 0, NULL, 'f'},
    {"help", 0, NULL, 'h'},
    {"remote", 1, NULL, 'r'},
    {"host", 1, NULL, 's'},
    {"port", 1, NULL, 'p'},
    {"user", 1, NULL, 'u'},
    {"version", 0, NULL, 'v'},
    {"verbose", 0, NULL, 'V'},
    {0, 0, 0, 0}
};
#endif

config_t global;
unsigned int Tag = 0;
static config_t *box = 0;
char Hostname[256];
int Verbose = 0;

static void
version (void)
{
    printf ("%s %s\n", PACKAGE, VERSION);
    exit (0);
}

static void
usage (void)
{
    printf ("%s %s IMAP4 to maildir synchronizer\n", PACKAGE, VERSION);
    puts ("Copyright (C) 2000 Michael R. Elkins <me@mutt.org>");
    printf ("usage: %s [ flags ] mailbox\n", PACKAGE);
    puts
	("  -c, --config CONFIG	read an alternate config file (default: ~/.isyncrc)");
    puts
	("  -d, --delete		delete local msgs that don't exist on the server");
    puts
	("  -e, --expunge		expunge	deleted messages from the server");
    puts ("  -f, --fast		only fetch new messages");
    puts ("  -h, --help		display this help message");
    puts ("  -p, --port PORT	server IMAP port");
    puts ("  -r, --remote BOX	remote mailbox");
    puts ("  -s, --host HOST	IMAP server address");
    puts ("  -u, --user USER	IMAP user name");
    puts ("  -v, --version		display version");
    puts
	("  -V, --verbose		verbose mode (display network traffic)");
    exit (0);
}

/* set defaults from the global configuration section */
static void
config_defaults (config_t * conf)
{
    conf->user = global.user;
    conf->pass = global.pass;
    conf->port = global.port;
    conf->box = global.box;
    conf->host = global.host;
    conf->max_size = global.max_size;
#if HAVE_LIBSSL
    conf->require_ssl = global.require_ssl;
    conf->use_imaps = global.use_imaps;
    conf->cert_file = global.cert_file;
#endif
}

static void
load_config (char *where)
{
    char path[_POSIX_PATH_MAX];
    char buf[1024];
    struct passwd *pw;
    config_t **cur = &box;
    char *p;
    int line = 0;
    FILE *fp;

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
	{
	    perror ("fopen");
	    return;
	}
    }
    while ((fgets (buf, sizeof (buf) - 1, fp)))
    {
	if (buf[0])
	    buf[strlen (buf) - 1] = 0;
	line++;
	if (buf[0] == '#')
	    continue;
	p = buf;
	while (*p && !isspace ((unsigned char)*p))
	    p++;
	while (isspace ((unsigned char)*p))
	    p++;
	if (!strncasecmp ("mailbox", buf, 7))
	{
	    if (*cur)
		cur = &(*cur)->next;
	    *cur = calloc (1, sizeof (config_t));
	    config_defaults (*cur);
	    (*cur)->path = strdup (p);
	}
	else if (!strncasecmp ("host", buf, 4))
	{
#if HAVE_LIBSSL
	    if (!strncasecmp ("imaps:", p, 6))
	    {
		p += 6;
		if (*cur)
		{
		    (*cur)->use_imaps = 1;
		    (*cur)->port = 993;
		}
		else
		{
		    global.use_imaps = 1;
		    global.port = 993;
		}
	    }
#endif
	    if (*cur)
		(*cur)->host = strdup (p);
	    else
		global.host = strdup (p);
	}
	else if (!strncasecmp ("user", buf, 4))
	{
	    if (*cur)
		(*cur)->user = strdup (p);
	    else
		global.user = strdup (p);
	}
	else if (!strncasecmp ("pass", buf, 4))
	{
	    if (*cur)
		(*cur)->pass = strdup (p);
	    else
		global.pass = strdup (p);
	}
	else if (!strncasecmp ("port", buf, 4))
	{
	    if (*cur)
		(*cur)->port = atoi (p);
	    else
		global.port = atoi (p);
	}
	else if (!strncasecmp ("box", buf, 3))
	{
	    if (*cur)
		(*cur)->box = strdup (p);
	    else
		global.box = strdup (p);
	}
	else if (!strncasecmp ("alias", buf, 5))
	{
	    if (*cur)
		(*cur)->alias = strdup (p);
	}
	else if (!strncasecmp ("maxsize", buf, 7))
	{
	    if (*cur)
		(*cur)->max_size = atol (p);
	    else
		global.max_size = atol (p);
	}
#if HAVE_LIBSSL
	else if (!strncasecmp ("CertificateFile", buf, 15))
	{
	    if (*cur)
		(*cur)->cert_file = strdup (p);
	    else
		global.cert_file = strdup (p);
	}
	else if (!strncasecmp ("RequireSSL", buf, 10))
	{
	    if (*cur)
		(*cur)->require_ssl = (strcasecmp (p, "yes") == 0);
	    else
		global.require_ssl = (strcasecmp (p, "yes") == 0);
	}
#endif
	else if (buf[0])
	    printf ("%s:%d:unknown command:%s", path, line, buf);
    }
    fclose (fp);
}

static config_t *
find_box (const char *s)
{
    config_t *p = box;

    for (; p; p = p->next)
	if (!strcmp (s, p->path) || (p->alias && !strcmp (s, p->alias)))
	    return p;
    return 0;
}

char *
next_arg (char **s)
{
    char *ret;

    if (!s)
	return 0;
    if (!*s)
	return 0;
    while (isspace ((unsigned char)**s))
	(*s)++;
    if (!**s)
    {
	*s = 0;
	return 0;
    }
    ret = *s;
    while (**s && !isspace ((unsigned char)**s))
	(*s)++;
    if (**s)
	*(*s)++ = 0;
    if (!**s)
	*s = 0;
    return ret;
}

int
main (int argc, char **argv)
{
    int i;
    config_t *box;
    mailbox_t *mail;
    imap_t *imap;
    int expunge = 0;		/* by default, don't delete anything */
    int fast = 0;
    int delete = 0;
    char *config = 0;
    struct passwd *pw;

    pw = getpwuid (getuid ());

    /* defaults */
    memset (&global, 0, sizeof (global));
    global.port = 143;
    global.box = "INBOX";
    global.user = strdup (pw->pw_name);
    global.max_size = 0;
#if HAVE_LIBSSL
    /* this will probably annoy people, but its the best default just in
     * case people forget to turn it on
     */
    global.require_ssl = 1;
#endif

#if HAVE_GETOPT_LONG
    while ((i = getopt_long (argc, argv, "defhp:u:r:s:vV", Opts, NULL)) != -1)
#else
    while ((i = getopt (argc, argv, "defhp:u:r:s:vV")) != -1)
#endif
    {
	switch (i)
	{
	case 'c':
	    config = optarg;
	    break;
	case 'd':
	    delete = 1;
	    break;
	case 'e':
	    expunge = 1;
	    break;
	case 'f':
	    fast = 1;
	    break;
	case 'p':
	    global.port = atoi (optarg);
	    break;
	case 'r':
	    global.box = optarg;
	    break;
	case 's':
	    global.host = optarg;
	    break;
	case 'u':
	    free (global.user);
	    global.user = optarg;
	    break;
	case 'V':
	    Verbose = 1;
	    break;
	case 'v':
	    version ();
	default:
	    usage ();
	}
    }

    if (!argv[optind])
    {
	puts ("No box specified");
	usage ();
    }

    gethostname (Hostname, sizeof (Hostname));

    load_config (config);

    box = find_box (argv[optind]);
    if (!box)
    {
	/* if enough info is given on the command line, don't worry if
	 * the mailbox isn't defined.
	 */
	if (!global.host)
	{
	    puts ("No such mailbox");
	    exit (1);
	}
	global.path = argv[optind];
	box = &global;
    }

    if (!box->pass)
    {
	char *pass = getpass ("Password:");

	if (!pass)
	{
	    puts ("Aborting, no password");
	    exit (1);
	}
	box->pass = strdup (pass);
    }

    printf ("Reading %s\n", box->path);
    mail = maildir_open (box->path, fast);
    if (!mail)
    {
	puts ("Unable to load mailbox");
	exit (1);
    }

    imap = imap_open (box, fast ? mail->maxuid + 1 : 1);
    if (!imap)
	exit (1);

    puts ("Synchronizing");
    i = delete ? SYNC_DELETE : 0;
    i |= expunge ? SYNC_EXPUNGE : 0;
    if (sync_mailbox (mail, imap, i, box->max_size))
	exit (1);

    if (!fast)
    {
	if (expunge && (imap->deleted || mail->deleted))
	{
	    /* remove messages marked for deletion */
	    printf ("Expunging %d messages from server\n", imap->deleted);
	    if (imap_expunge (imap))
		exit (1);
	    printf ("Expunging %d messages from local mailbox\n",
		    mail->deleted);
	    if (maildir_expunge (mail, 0))
		exit (1);
	}
	/* remove messages deleted from server.  this can safely be an
	 * `else' clause since dead messages are marked as deleted by
	 * sync_mailbox.
	 */
	else if (delete)
	    maildir_expunge (mail, 1);

	/* write changed flags back to the mailbox */
	printf ("Committing changes to %s\n", mail->path);
	if (maildir_sync (mail))
	    exit (1);
    }

    /* gracefully close connection to the IMAP server */
    imap_close (imap);

    exit (0);
}
