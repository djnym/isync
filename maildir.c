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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "isync.h"

static int
do_lock (int fd, int flag)
{
    struct flock lck;
    struct stat sb;

    if (fstat (fd, &sb))
    {
	perror ("fstat");
	return -1;
    }

    memset (&lck, 0, sizeof (lck));
    lck.l_type = flag;
    lck.l_whence = SEEK_SET;
    lck.l_start = 0;
    lck.l_len = sb.st_size;

    if (fcntl (fd, F_SETLK, &lck))
    {
	perror ("fcntl");
	close (fd);
	return -1;
    }

    return 0;
}

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

static unsigned int
read_uid (const char *path, const char *file)
{
    char full[_POSIX_PATH_MAX];
    int fd;
    int ret;
    int len;
    char buf[64];
    unsigned int uid = 0;

    snprintf (full, sizeof (full), "%s/%s", path, file);
    fd = open (full, O_RDONLY);
    if (fd == -1)
    {
	if (errno != ENOENT)
	{
	    perror ("open");
	    return -1;
	}
	return 0;		/* doesn't exist */
    }
    ret = do_lock (fd, F_RDLCK);
    if (!ret)
    {
	len = read (fd, buf, sizeof (buf) - 1);
	if (len == -1)
	    ret = -1;
	else
	{
	    buf[len] = 0;
	    uid = atol (buf);
	}
    }
    ret |= do_lock (fd, F_UNLCK);
    close (fd);
    return ret ? ret : uid;

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

    /* check for the uidvalidity value */
    m->uidvalidity = read_uid (path, "isyncuidvalidity");
    if (m->uidvalidity == (unsigned int) -1)
    {
	free (m->path);
	free (m);
	return NULL;
    }

    /* load the current maxuid */
    if ((m->maxuid = read_uid (path, "isyncmaxuid")) == (unsigned int) -1)
    {
	free (m->path);
	free (m);
	return NULL;
    }

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
	    free (m->path);
	    free (m);
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
	    p->flags = 0;
	    p->new = (count == 0);

	    /* filename format is something like:
	     * <unique-prefix>,U=<n>:2,<flags>
	     * This is completely non-standard, but in order for mail
	     * clients to understand the flags, we have to use the
	     * standard :info as described by the qmail spec
	     */
	    s = strstr (p->file, ",U=");
	    if (!s)
		s = strstr (p->file, "UID");
	    if (!s)
		puts ("Warning, no UID for message");
	    else
	    {
		p->uid = strtol (s + 3, &s, 10);
		if (p->uid > m->maxuid)
		{
		    m->maxuid = p->uid;
		    m->maxuidchanged = 1;
		}
		/* Courier-IMAP names it files
		 * 	unique,S=<size>:info
		 * so we need to put the UID before the size, hence here
		 * we check for a comma as a valid terminator as well,
		 * since the format will be
		 * 	unique,U=<uid>,S=<size>:info
		 */
		if (*s && *s != ':' && *s != ',')
		{
		    puts ("Warning, unable to parse UID");
		    p->uid = -1;	/* reset */
		}
	    }

	    s = strchr (p->file, ':');
	    if (s)
		parse_info (p, s + 1);
	    if (p->flags & D_DELETED)
		m->deleted++;
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

static int
update_maxuid (mailbox_t * mbox)
{
    int fd;
    char buf[64];
    size_t len;
    unsigned int uid;
    char path[_POSIX_PATH_MAX];
    int ret = 0;

    snprintf (path, sizeof (path), "%s/isyncmaxuid", mbox->path);
    fd = open (path, O_RDWR | O_CREAT, 0600);
    if (fd == -1)
    {
	perror ("open");
	return -1;
    }

    /* lock the file */
    if (do_lock (fd, F_WRLCK))
    {
	close (fd);
	return -1;
    }

    /* read the file again just to make sure it wasn't updated while
     * we were doing something else
     */
    len = read (fd, buf, sizeof (buf) - 1);
    buf[len] = 0;
    uid = atol (buf);
    if (uid > mbox->maxuid)
    {
	puts ("Error, maxuid is now higher (fatal)");
	ret = -1;
    }

    if (!ret)
    {
	/* rewind */
	lseek (fd, 0, SEEK_SET);

	/* write out the file */
	snprintf (buf, sizeof (buf), "%u\n", mbox->maxuid);
	len = write (fd, buf, strlen (buf));
	if (len == (size_t) - 1)
	{
	    perror ("write");
	    ret = -1;
	}
	else
	{
	    ret = ftruncate (fd, len);
	    if (ret)
		perror ("ftruncate");
	}
    }

    ret |= do_lock (fd, F_UNLCK);
    ret |= close (fd);

    return ret;
}

int
maildir_sync (mailbox_t * mbox)
{
    message_t *cur = mbox->msgs;
    char path[_POSIX_PATH_MAX];
    char oldpath[_POSIX_PATH_MAX];
    char *p;
    int ret = 0;

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

		/* generate new path - always put this in the cur/ directory
		 * because its no longer new
		 */
		snprintf (path, sizeof (path), "%s/cur/%s:2,%s%s%s%s",
			  mbox->path,
			  cur->file, (cur->flags & D_FLAGGED) ? "F" : "",
			  (cur->flags & D_ANSWERED) ? "R" : "",
			  (cur->flags & D_SEEN) ? "S" : "",
			  (cur->flags & D_DELETED) ? "T" : "");

		if (rename (oldpath, path))
		    perror ("rename");
	    }
	}
    }

    if (mbox->maxuidchanged)
	ret = update_maxuid (mbox);

    return ret;
}

int
maildir_set_uidvalidity (mailbox_t * mbox, unsigned int uidvalidity)
{
    char path[_POSIX_PATH_MAX];
    char buf[16];
    int fd;
    int ret;

    snprintf (path, sizeof (path), "%s/isyncuidvalidity", mbox->path);
    fd = open (path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == -1)
    {
	perror ("open");
	return -1;
    }
    snprintf (buf, sizeof (buf), "%u\n", uidvalidity);

    ret = write (fd, buf, strlen (buf));

    if (ret == -1)
	perror ("write");
    else if ((size_t) ret != strlen (buf))
	ret = -1;
    else
	ret = 0;

    if (close (fd))
    {
	perror ("close");
	ret = -1;
    }

    if (ret)
	if (unlink (path))
	    perror ("unlink");

    return (ret);
}

void
maildir_close (mailbox_t * mbox)
{
    free (mbox->path);
    free_message (mbox->msgs);
    memset (mbox, 0xff, sizeof (mailbox_t));
    free (mbox);
}
