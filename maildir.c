/* isync - IMAP4 to maildir mailbox synchronizer
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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "isync.h"

/* 2,<flags> */
static void
parse_info (message_t * m, char *s)
{
    if (*s == '2' && *(s + 1) == ',')
    {
	s += 2;
	while (*s)
	{
	    if (*s == 'F')
		m->flags |= D_FLAGGED;
	    else if (*s == 'R')
		m->flags |= D_ANSWERED;
	    else if (*s == 'T')
		m->flags |= D_DELETED;
	    else if (*s == 'S')
		m->flags |= D_SEEN;
	    s++;
	}
    }
}

/* open a maildir mailbox.  if `fast' is nonzero, we just check to make
 * sure its a valid mailbox and don't actually parse it.  any IMAP messages
 * with the \Recent flag set are guaranteed not to be in the mailbox yet,
 * so we can save a lot of time when the user just wants to fetch new messages
 * without syncing the flags.
 */
mailbox_t *
maildir_open (const char *path, int fast)
{
    char buf[_POSIX_PATH_MAX];
    DIR *d;
    struct dirent *e;
    message_t **cur;
    message_t *p;
    mailbox_t *m;
    char *s;
    int count = 0;

    /* check to make sure this looks like a valid maildir box */
    snprintf (buf, sizeof (buf), "%s/new", path);
    if (access (buf, F_OK))
    {
	perror ("access");
	return 0;
    }
    snprintf (buf, sizeof (buf), "%s/cur", path);
    if (access (buf, F_OK))
    {
	perror ("access");
	return 0;
    }
    m = calloc (1, sizeof (mailbox_t));
    m->path = strdup (path);

    if (fast)
	return m;

    cur = &m->msgs;
    for (; count < 2; count++)
    {
	/* read the msgs from the new subdir */
	snprintf (buf, sizeof (buf), "%s/%s", path,
		  (count == 0) ? "new" : "cur");
	d = opendir (buf);
	if (!d)
	{
	    perror ("opendir");
	    return 0;
	}
	while ((e = readdir (d)))
	{
	    if (*e->d_name == '.')
		continue;	/* skip dot-files */
	    *cur = calloc (1, sizeof (message_t));
	    p = *cur;
	    p->file = strdup (e->d_name);
	    p->uid = -1;
	    p->flags = (count == 1) ? D_SEEN : 0;
	    p->new = (count == 0);

	    /* filename format is something like:
	     * <unique-prefix>.UID<n>:2,<flags>
	     * This is completely non-standard, but in order for mail
	     * clients to understand the flags, we have to use the
	     * standard :info as described by the qmail spec
	     */
	    s = strstr (p->file, "UID");
	    if (!s)
		puts ("warning, no uid for message");
	    else
	    {
		p->uid = strtol (s + 3, &s, 10);
		if (*s && *s != ':')
		{
		    puts ("warning, unable to parse uid");
		    p->uid = -1;	/* reset */
		}
	    }

	    s = strchr (p->file, ':');
	    if (s)
		parse_info (p, s + 1);
	    cur = &p->next;
	}
	closedir (d);
    }
    return m;
}

/* permanently remove messages from a maildir mailbox.  if `dead' is nonzero,
 * we only remove the messags marked dead.
 */
int
maildir_expunge (mailbox_t * mbox, int dead)
{
    message_t **cur = &mbox->msgs;
    message_t *tmp;
    char path[_POSIX_PATH_MAX];

    while (*cur)
    {
	if ((dead == 0 && (*cur)->flags & D_DELETED) ||
	    (dead && (*cur)->dead))
	{
	    tmp = *cur;
	    *cur = (*cur)->next;
	    snprintf (path, sizeof (path), "%s/%s/%s",
		      mbox->path, tmp->new ? "new" : "cur", tmp->file);
	    if (unlink (path))
		perror ("unlink");
	    free (tmp->file);
	    free (tmp);
	}
	else
	    cur = &(*cur)->next;
    }
    return 0;
}

int
maildir_sync (mailbox_t * mbox)
{
    message_t *cur = mbox->msgs;
    char path[_POSIX_PATH_MAX];
    char oldpath[_POSIX_PATH_MAX];
    char *p;

    if (mbox->changed)
    {
	for (; cur; cur = cur->next)
	{
	    if (cur->changed)
	    {
		/* generate old path */
		snprintf (oldpath, sizeof (oldpath), "%s/%s/%s",
			  mbox->path, cur->new ? "new" : "cur", cur->file);

		/* truncate old flags (if present) */
		p = strchr (cur->file, ':');
		if (p)
		    *p = 0;

		p = strrchr (cur->file, '/');

		/* generate new path */
		snprintf (path, sizeof (path), "%s/%s%s:2,%s%s%s%s",
			  mbox->path, (cur->flags & D_SEEN) ? "cur" : "new",
			  cur->file, (cur->flags & D_FLAGGED) ? "F" : "",
			  (cur->flags & D_ANSWERED) ? "R" : "",
			  (cur->flags & D_SEEN) ? "S" : "",
			  (cur->flags & D_DELETED) ? "T" : "");

		if (rename (oldpath, path))
		    perror ("rename");
	    }
	}
    }
    return 0;
}
