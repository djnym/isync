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
    {"all", 0, NULL, 'a'},
    {"config", 1, NULL, 'c'},
    {"delete", 0, NULL, 'd'},
    {"expunge", 0, NULL, 'e'},
    {"fast", 0, NULL, 'f'},
    {"help", 0, NULL, 'h'},
    {"remote", 1, NULL, 'r'},
    {"host", 1, NULL, 's'},
    {"port", 1, NULL, 'p'},
    {"quiet", 0, NULL, 'q'},
    {"user", 1, NULL, 'u'},
    {"version", 0, NULL, 'v'},
    {"verbose", 0, NULL, 'V'},
    {0, 0, 0, 0}
};
#endif

config_t global;
unsigned int Tag = 0;
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
    puts ("Copyright (C) 2000-1 Michael R. Elkins <me@mutt.org>");
    printf ("usage: %s [ flags ] mailbox [mailbox ...]\n", PACKAGE);
    puts ("  -a, --all	Synchronize all defined mailboxes");
    puts ("  -c, --config CONFIG	read an alternate config file (default: ~/.isyncrc)");
    puts ("  -d, --delete		delete local msgs that don't exist on the server");
    puts ("  -e, --expunge		expunge	deleted messages from the server");
    puts ("  -f, --fast		only fetch new messages");
    puts ("  -h, --help		display this help message");
    puts ("  -p, --port PORT	server IMAP port");
    puts ("  -r, --remote BOX	remote mailbox");
    puts ("  -s, --host HOST	IMAP server address");
    puts ("  -u, --user USER	IMAP user name");
    puts ("  -v, --version		display version");
    puts ("  -V, --verbose		verbose mode (display network traffic)");
    puts ("Compile time options:");
#if HAVE_LIBSSL
    puts ("  +HAVE_LIBSSL");
#else
    puts ("  -HAVE_LIBSSL");
#endif
    exit (0);
}

char *
next_arg (char **s)
{
    char *ret;

    if (!s)
	return 0;
    if (!*s)
	return 0;
    while (isspace ((unsigned char) **s))
	(*s)++;
    if (!**s)
    {
	*s = 0;
	return 0;
    }
    if (**s == '"')
    {
	++*s;
	ret = *s;
	*s = strchr (*s, '"');
    }
    else
    {
	ret = *s;
	while (**s && !isspace ((unsigned char) **s))
	    (*s)++;
    }
    if (*s)
    {
	if (**s)
	    *(*s)++ = 0;
	if (!**s)
	    *s = 0;
    }
    return ret;
}

int
main (int argc, char **argv)
{
    int i;
    config_t *box = 0;
    mailbox_t *mail;
    imap_t *imap = 0;
    int expunge = 0;		/* by default, don't delete anything */
    int fast = 0;
    int delete = 0;
    char *config = 0;
    struct passwd *pw;
    int quiet = 0;
    int all = 0;

    pw = getpwuid (getuid ());

    /* defaults */
    memset (&global, 0, sizeof (global));
    global.port = 143;
    global.box = "INBOX";
    global.user = strdup (pw->pw_name);
    global.maildir = strdup (pw->pw_dir);
    global.max_size = 0;
    global.max_messages = 0;
    global.use_namespace = 1;
#if HAVE_LIBSSL
    /* this will probably annoy people, but its the best default just in
     * case people forget to turn it on
     */
    global.require_ssl = 1;
    global.use_sslv2 = 0;
    global.use_sslv3 = 0;
    global.use_tlsv1 = 1;
#endif

#define FLAGS "ac:defhp:qu:r:s:vV"

#if HAVE_GETOPT_LONG
    while ((i = getopt_long (argc, argv, FLAGS, Opts, NULL)) != -1)
#else
    while ((i = getopt (argc, argv, FLAGS)) != -1)
#endif
    {
	switch (i)
	{
	    case 'a':
		all = 1;
		break;
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
	    case 'q':
		quiet = 1;
		Verbose = 0;
		break;
	    case 'r':
		global.box = optarg;
		break;
	    case 's':
#if HAVE_LIBSSL
		if (!strncasecmp ("imaps:", optarg, 6))
		{
		    global.use_imaps = 1;
		    optarg += 6;
		}
#endif
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

    if (!argv[optind] && !all)
    {
	puts ("No mailbox specified");
	usage ();
    }

    gethostname (Hostname, sizeof (Hostname));

    load_config (config);

    for (box = boxes; (all && box) || (!all && argv[optind]); optind++)
    {
	if (!all)
	{
	    if (NULL == (box = find_box (argv[optind])))
	    {
		/* if enough info is given on the command line, don't worry if
		 * the mailbox isn't defined.
		 */
		if (!global.host)
		{
		    fprintf (stderr, "%s: no such mailbox\n", argv[optind]);
		    continue;
		}
		global.path = argv[optind];
		box = &global;
	    }
	}

	if (!box->pass)
	{
	    /* if we don't have a global password set, prompt the user for
	     * it now.
	     */
	    if (!global.pass)
	    {
		global.pass = getpass ("Password:");
		if (!global.pass)
		{
		    puts ("Aborting, no password");
		    exit (1);
		}
	    }
	    box->pass = strdup (global.pass);
	}

	if (!quiet)
	    printf ("Reading %s\n", box->path);
	mail = maildir_open (box->path, fast);
	if (!mail)
	{
	    fprintf (stderr, "%s: unable to load mailbox\n", box->path);
	    goto cleanup;
	}

	imap = imap_open (box, fast ? mail->maxuid + 1 : 1, imap);
	if (!imap)
	{
	    fprintf (stderr, "%s: skipping mailbox due to IMAP error\n",
		     box->path);
	    goto cleanup;
	}

	if (!quiet)
	    puts ("Synchronizing");
	i = 0;
	if (quiet)
	    i |= SYNC_QUIET;
	i |= (delete || box->delete) ? SYNC_DELETE : 0;
	i |= (expunge || box->expunge) ? SYNC_EXPUNGE : 0;
	if (sync_mailbox (mail, imap, i, box->max_size, box->max_messages))
	    exit (1);

	if (!fast)
	{
	    if ((expunge || box->expunge) && (imap->deleted || mail->deleted))
	    {
		/* remove messages marked for deletion */
		if (!quiet)
		    printf ("Expunging %d messages from server\n",
			    imap->deleted);
		if (imap_expunge (imap))
		    exit (1);
		if (!quiet)
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
	}

	/* write changed flags back to the mailbox */
	if (!quiet)
	    printf ("Committing changes to %s\n", mail->path);

	if (maildir_close (mail))
	    exit (1);

cleanup:
	if (all)
	    box = box->next;
    }

    /* gracefully close connection to the IMAP server */
    imap_close (imap);

    free_config ();

#if DEBUG
    debug_cleanup ();
#endif

    exit (0);
}
