/* $Id$
 *
 * isync - IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "isync.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

int Quiet;

void
info (const char *msg, ...)
{
  va_list va;

  if (!Quiet)
  {
    va_start (va, msg);
    vprintf (msg, va);
    va_end (va);
  }
}

void
infoc (char c)
{
    if (!Quiet)
	putchar (c);
}

void
warn (const char *msg, ...)
{
  va_list va;

  if (Quiet < 2)
  {
    va_start (va, msg);
    vfprintf (stderr, msg, va);
    va_end (va);
  }
}

#if HAVE_GETOPT_LONG
# define _GNU_SOURCE
# include <getopt.h>
struct option Opts[] = {
    {"all", 0, NULL, 'a'},
    {"list", 0, NULL, 'l'},
    {"config", 1, NULL, 'c'},
    {"create", 0, NULL, 'C'},
    {"create-local", 0, NULL, 'L'},
    {"create-remote", 0, NULL, 'R'},
    {"delete", 0, NULL, 'd'},
    {"expunge", 0, NULL, 'e'},
    {"fast", 0, NULL, 'f'},
    {"help", 0, NULL, 'h'},
    {"remote", 1, NULL, 'r'},
    {"folder", 1, NULL, 'F'},
    {"maildir", 1, NULL, 'M'},
    {"one-to-one", 0, NULL, '1'},
    {"inbox", 1, NULL, 'I'},
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
char Hostname[256];
int Verbose = 0;

static void
version (void)
{
    puts (PACKAGE " " VERSION);
    exit (0);
}

static void
usage (int code)
{
    fputs (
PACKAGE " " VERSION " IMAP4 to maildir synchronizer\n"
"Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>\n"
"Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>\n"
"usage:\n"
" " PACKAGE " [ flags ] mailbox [mailbox ...]\n"
" " PACKAGE " [ flags ] -a\n"
" " PACKAGE " [ flags ] -l\n"
"  -a, --all		synchronize all defined mailboxes\n"
"  -l, --list		list all defined mailboxes and exit\n"
"  -L, --create-local	create local maildir mailbox if nonexistent\n"
"  -R, --create-remote	create remote imap mailbox if nonexistent\n"
"  -C, --create		create both local and remote mailboxes if nonexistent\n"
"  -d, --delete		delete local msgs that don't exist on the server\n"
"  -e, --expunge		expunge	deleted messages\n"
"  -f, --fast		only fetch new messages\n"
"  -r, --remote BOX	remote mailbox\n"
"  -F, --folder DIR	remote IMAP folder containing mailboxes\n"
"  -M, --maildir DIR	local directory containing mailboxes\n"
"  -1, --one-to-one	map every IMAP <folder>/box to <maildir>/box\n"
"  -I, --inbox BOX	map IMAP INBOX to <maildir>/BOX (exception to -1)\n"
"  -s, --host HOST	IMAP server address\n"
"  -p, --port PORT	server IMAP port\n"
"  -u, --user USER	IMAP user name\n"
"  -c, --config CONFIG	read an alternate config file (default: ~/.isyncrc)\n"
"  -V, --verbose		verbose mode (display network traffic)\n"
"  -q, --quiet		don't display progress info\n"
"  -v, --version		display version\n"
"  -h, --help		display this help message\n"
"Compile time options:\n"
#if HAVE_LIBSSL
"  +HAVE_LIBSSL\n"
#else
"  -HAVE_LIBSSL\n"
#endif
	, code ? stderr : stdout);
    exit (code);
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
    int ret;
    config_t *box = 0;
    mailbox_t *mail = 0;
    imap_t *imap = 0;
    int expunge = 0;		/* by default, don't delete anything */
    int fast = 0;
    int delete = 0;
    char *config = 0;
    struct passwd *pw;
    int all = 0;
    int list = 0;
    int o2o = 0;
    int mbox_open_mode = 0;
    int imap_flags = 0;

    pw = getpwuid (getuid ());

    /* defaults */
    memset (&global, 0, sizeof (global));
    /* XXX the precedence is borked: 
       it's defaults < cmdline < file instead of defaults < file < cmdline */
    global.port = 143;
    global.box = "INBOX";
    global.folder = "";
    global.user = strdup (pw->pw_name);
    global.maildir = strdup (pw->pw_dir);
    global.use_namespace = 1;
#if HAVE_LIBSSL
    /* this will probably annoy people, but its the best default just in
     * case people forget to turn it on
     */
    global.require_ssl = 1;
    global.use_tlsv1 = 1;
#endif

#define FLAGS "alCLRc:defhp:qu:r:F:M:1I:s:vV"

#if HAVE_GETOPT_LONG
    while ((i = getopt_long (argc, argv, FLAGS, Opts, NULL)) != -1)
#else
    while ((i = getopt (argc, argv, FLAGS)) != -1)
#endif
    {
	switch (i)
	{
	    case 'l':
		list = 1;
		/* plopp */
	    case 'a':
		all = 1;
		break;
	    case '1':
		o2o = 1;
		break;
	    case 'C':
		mbox_open_mode |= OPEN_CREATE;
		imap_flags |= IMAP_CREATE;
		break;
	    case 'L':
		mbox_open_mode |= OPEN_CREATE;
		break;
	    case 'R':
		imap_flags |= IMAP_CREATE;
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
		mbox_open_mode |= OPEN_FAST;
		fast = 1;
		break;
	    case 'p':
		global.port = atoi (optarg);
		break;
	    case 'q':
		Quiet++;
		Verbose = 0;
		break;
	    case 'r':
		global.box = optarg;
		break;
	    case 'F':
		global.folder = optarg;
		break;
	    case 'M':
		global.maildir = optarg;
		break;
	    case 'I':
		global.inbox = optarg;
		break;
	    case 's':
#if HAVE_LIBSSL
		if (!strncasecmp ("imaps:", optarg, 6))
		{
		    global.use_imaps = 1;
		    global.port = 993;
		    global.use_sslv2 = 1;
		    global.use_sslv3 = 1;
		    optarg += 6;
		}
#endif
		global.host = optarg;
		break;
	    case 'u':
		global.user = optarg;
		break;
	    case 'V':
		Verbose = 1;
		break;
	    case 'v':
		version ();
	    case 'h':
		usage (0);
	    default:
		usage (1);
	}
    }

    if (!argv[optind] && !all)
    {
	fprintf (stderr, "No mailbox specified. Try isync -h\n");
	return 1;
    }

    gethostname (Hostname, sizeof (Hostname));

    load_config (config, &o2o);

    if (all && o2o)
    {
	DIR *dir;
	struct dirent *de;

	if (global.inbox) {
	    boxes = malloc (sizeof (config_t));
	    memcpy (boxes, &global, sizeof (config_t));
	    boxes->box = "INBOX";
	    boxes->path = global.inbox;
	}

	if (!(dir = opendir (global.maildir))) {
	    fprintf (stderr, "%s: %s\n", global.maildir, strerror(errno));
	    return 1;
	}
	while ((de = readdir (dir))) {
	    struct stat st;
	    char buf[PATH_MAX];

	    if (*de->d_name == '.')
		continue;
	    if (global.inbox && !strcmp (global.inbox, de->d_name))
		continue;
	    snprintf (buf, sizeof(buf), "%s/%s/cur", global.maildir, de->d_name);
	    if (stat (buf, &st) || !S_ISDIR (st.st_mode))
		continue;
	    box = malloc (sizeof (config_t));
	    memcpy (box, &global, sizeof (config_t));
	    box->path = strdup (de->d_name);
	    box->box = box->path;
	    box->next = boxes;
	    boxes = box;
	}
	closedir (dir);

	imap = imap_connect (&global);
	if (!imap)
	    return 1;
	if (imap_list (imap))
	    return 1;
    }
    if (list)
    {
	for (box = boxes; box; box = box->next)
	    puts (box->path);
	return 0;
    }
    ret = 0;
    for (box = boxes; (all && box) || (!all && argv[optind]); optind++)
    {
	if (!all)
	{
	    if (o2o || NULL == (box = find_box (argv[optind])))
	    {
		/* if enough info is given on the command line, don't worry if
		 * the mailbox isn't defined.
		 */
		if (!global.host)
		{
		    fprintf (stderr, "%s: no such mailbox\n", argv[optind]);
		    /* continue is ok here because we are not handling the
		     * `all' case.
		     */
		    continue;
		}
		global.path = argv[optind];
		box = &global;
		if (o2o)
		    global.box = 
			(global.inbox && !strcmp (global.path, global.inbox)) ?
			"INBOX" : global.path;
	    }
	}

	do {
	    info ("Mailbox %s\n", box->path);
	    mail = maildir_open (box->path, mbox_open_mode);
	    if (!mail)
	    {
		fprintf (stderr, "%s: unable to open mailbox\n", box->path);
		ret = 1;
		break;
	    }

	    if (box->max_size)
		imap_flags |= IMAP_GET_SIZE;
	    imap = imap_open (box, fast ? mail->maxuid + 1 : 1, imap, imap_flags);
	    if (!imap)
	    {
		fprintf (stderr, "%s: skipping mailbox due to IMAP error\n",
			 box->path);
		ret = 1;
		break;
	    }

	    info ("Synchronizing\n");
	    i = (delete || box->delete) ? SYNC_DELETE : 0;
	    i |= (expunge || box->expunge) ? SYNC_EXPUNGE : 0;
	    if (sync_mailbox (mail, imap, i, box->max_size, box->max_messages))
	    {
		imap_close (imap); /* Just to be safe.  Don't really know
				    * what the problem was.
				    */
		imap = NULL;	/* context no longer valid */
		ret = 1;
		break;
	    }

	    if (!fast)
	    {
		if ((expunge || box->expunge) &&
		    (imap->deleted || mail->deleted))
		{
		    /* remove messages marked for deletion */
		    info ("Expunging %d messages from server\n", imap->deleted);
		    if (imap_expunge (imap))
		    {
			imap_close (imap);
			imap = NULL;
			ret = 1;
			break;
		    }
		    info ("Expunging %d messages from local mailbox\n",
			  mail->deleted);
		    if (maildir_expunge (mail, 0)) {
			ret = 1;
			break;
		    }
		}
		/* remove messages deleted from server.  this can safely be an
		 * `else' clause since dead messages are marked as deleted by
		 * sync_mailbox.
		 */
		else if (delete) {
		    if (maildir_expunge (mail, 1)) {
			ret = 1;
			break;
		    }
		}
	    }

	} while (0);

	/* we never sync the same mailbox twice, so close it now */
	if (mail)
	    maildir_close (mail);

	/* the imap connection is not closed so we can keep the connection
	 * open, and there is no IMAP command for un-SELECT-ing a mailbox.
	 */
	if (all)
	    box = box->next;
    }
    /* gracefully close connection to the IMAP server */
    imap_close (imap);
    return ret;
}
