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
#include <time.h>
#include "isync.h"
#include "dotlock.h"

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

/*
 * There are three possible results of this function:
 * >1	uid was already seen
 * 0	uid was not yet seen
 * -1	unable to read uid because of some other error
 */

static int
read_uid (const char *path, const char *file, unsigned int *uid /* out */)
{
    char full[_POSIX_PATH_MAX];
    int fd;
    int ret = -1;
    int len;
    char buf[64], *ptr;

    snprintf (full, sizeof (full), "%s/%s", path, file);
    fd = open (full, O_RDONLY);
    if (fd == -1)
    {
	if (errno != ENOENT)
	{
	    perror (full);
	    return -1;
	}
	return 0;		/* doesn't exist */
    }
    len = read (fd, buf, sizeof (buf) - 1);
    if (len == -1)
	perror ("read");
    else
    {
	buf[len] = 0;
	errno  = 0;
	*uid = strtoul (buf, &ptr, 10);
	if (errno)
	  perror ("strtoul");
	else if (ptr && *ptr == '\n')
	  ret = 1;
	/* else invalid value */
    }
    close (fd);
    return ret;
}

/*
 * open a maildir mailbox.
 * if OPEN_FAST is set, we just check to make
 * sure its a valid mailbox and don't actually parse it.  any IMAP messages
 * with the \Recent flag set are guaranteed not to be in the mailbox yet,
 * so we can save a lot of time when the user just wants to fetch new messages
 * without syncing the flags.
 * if OPEN_CREATE is set, we create the mailbox if it doesn't already exist.
 */
mailbox_t *
maildir_open (const char *path, int flags)
{
    char buf[_POSIX_PATH_MAX];
    DIR *d;
    struct dirent *e;
    message_t **cur;
    message_t *p;
    mailbox_t *m;
    char *s;
    int count = 0;
    struct stat sb;
    const char *subdirs[] = { "cur", "new", "tmp" };
    int i;
    datum key;

    m = calloc (1, sizeof (mailbox_t));
    m->lockfd = -1;
    /* filename expansion happens here, not in the config parser */
    m->path = expand_strdup (path);

    if (stat (m->path, &sb))
    {
	if (errno == ENOENT && (flags & OPEN_CREATE))
	{
	    if (mkdir (m->path, S_IRUSR | S_IWUSR | S_IXUSR))
	    {
		fprintf (stderr, "ERROR: mkdir %s: %s (errno %d)\n",
			 m->path, strerror (errno), errno);
		goto err;
	    }

	    for (i = 0; i < 3; i++)
	    {
		snprintf (buf, sizeof (buf), "%s/%s", m->path, subdirs[i]);
		if (mkdir (buf, S_IRUSR | S_IWUSR | S_IXUSR))
		{
		    fprintf (stderr, "ERROR: mkdir %s: %s (errno %d)\n",
			     buf, strerror (errno), errno);
		    goto err;
		}
	    }

	}
	else
	{
	    fprintf (stderr, "ERROR: stat %s: %s (errno %d)\n", m->path,
		     strerror (errno), errno);
	    goto err;
	}
    }
    else
    {
	/* check to make sure this looks like a valid maildir box */
	for (i = 0; i < 3; i++)
	{
	    snprintf (buf, sizeof (buf), "%s/%s", m->path, subdirs[i]);
	    if (stat (buf, &sb))
	    {
		fprintf (stderr, "ERROR: stat %s: %s (errno %d)\n", buf,
			 strerror (errno), errno);
		fprintf (stderr,
			 "ERROR: %s does not appear to be a valid maildir style mailbox\n",
			 m->path);
		goto err;
	    }
	}
    }

    /*
     * we need a mutex on the maildir because of the state files that isync
     * uses.
     */
    snprintf (buf, sizeof (buf), "%s/isynclock", m->path);
    if (dotlock_lock (buf, &m->lockfd))
	goto err;

    /* check for the uidvalidity value */
    i = read_uid (m->path, "isyncuidvalidity", &m->uidvalidity);
    if (i == -1)
      goto err;
    else if (i > 0)
      m->uidseen = 1;

    /* load the current maxuid */
    if (read_uid (m->path, "isyncmaxuid", &m->maxuid) == -1)
	goto err;

    if (flags & OPEN_FAST)
	return m;

    snprintf (buf, sizeof (buf), "%s/isyncuidmap", m->path);
    m->db = dbm_open (buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (m->db == NULL)
    {
	fputs ("ERROR: unable to open UID db\n", stderr);
	goto err;
    }

    cur = &m->msgs;
    for (; count < 2; count++)
    {
	/* read the msgs from the new subdir */
	snprintf (buf, sizeof (buf), "%s/%s", m->path,
		  (count == 0) ? "new" : "cur");
	d = opendir (buf);
	if (!d)
	{
	    perror ("opendir");
	    goto err;
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

	    /* determine the UID for this message.  The basename (sans
	     * flags) is used as the key in the db
	     */
	    key.dptr = p->file;
	    s = strchr (key.dptr, ':');
	    key.dsize = s ? (size_t) (s - key.dptr) : strlen (key.dptr);
	    key = dbm_fetch (m->db, key);
	    if (key.dptr)
	    {
		p->uid = *(int *) key.dptr;
		if (p->uid > m->maxuid)
		    m->maxuid = p->uid;
	    }
	    else
		puts ("Warning, no UID for message");

	    if (s)
		parse_info (p, s + 1);
	    if (p->flags & D_DELETED)
		m->deleted++;
	    cur = &p->next;
	}
	closedir (d);
    }
    return m;

  err:
    if (m->db)
	dbm_close (m->db);
    dotlock_unlock (&m->lockfd);
    free (m->path);
    free (m);
    return NULL;
}

/* permanently remove messages from a maildir mailbox.  if `dead' is nonzero,
 * we only remove the messags marked dead.
 */
int
maildir_expunge (mailbox_t * mbox, int dead)
{
    message_t **cur = &mbox->msgs;
    message_t *tmp;
    char *s;
    datum key;
    char path[_POSIX_PATH_MAX];

    while (*cur)
    {
	if ((dead == 0 && (*cur)->flags & D_DELETED) ||
	    (dead && (*cur)->dead))
	{
	    tmp = *cur;
	    snprintf (path, sizeof (path), "%s/%s/%s",
		      mbox->path, tmp->new ? "new" : "cur", tmp->file);
	    if (unlink (path))
		perror (path);
	    /* remove the message from the UID map */
	    key.dptr = tmp->file;
	    s = strchr (key.dptr, ':');
	    key.dsize = s ? (size_t) (s - key.dptr) : strlen (key.dptr);
	    dbm_delete (mbox->db, key);
	    *cur = (*cur)->next;
	    free (tmp->file);
	    free (tmp);
	}
	else
	    cur = &(*cur)->next;
    }
    return 0;
}

int
maildir_update_maxuid (mailbox_t * mbox)
{
    int fd;
    char buf[64];
    size_t len;
    char path[_POSIX_PATH_MAX];
    int ret = 0;

    snprintf (path, sizeof (path), "%s/isyncmaxuid", mbox->path);
    fd = open (path, O_WRONLY | O_CREAT, 0600);
    if (fd == -1)
    {
	perror ("open");
	return -1;
    }

    /* write out the file */
    snprintf (buf, sizeof (buf), "%u\n", mbox->maxuid);
    len = write (fd, buf, strlen (buf));
    if (len == (size_t) - 1)
    {
	perror ("write");
	ret = -1;
    }

    if (close (fd))
	ret = -1;

    return ret;
}

#define _24_HOURS (3600 * 24)

static void
maildir_clean_tmp (const char *mbox)
{
    char path[_POSIX_PATH_MAX];
    DIR *dirp;
    struct dirent *entry;
    struct stat info;
    time_t now;

    snprintf (path, sizeof (path), "%s/tmp", mbox);
    dirp = opendir (path);
    if (dirp == NULL)
    {
	fprintf (stderr, "maildir_clean_tmp: opendir: %s: %s (errno %d)\n",
		 path, strerror (errno), errno);
	return;
    }
    /* assuming this scan will take less than a second, we only need to
     * check the time once before the following loop.
     */
    time (&now);
    while ((entry = readdir (dirp)))
    {
	snprintf (path, sizeof (path), "%s/tmp/%s", mbox, entry->d_name);
	if (stat (path, &info))
	    fprintf (stderr, "maildir_clean_tmp: stat: %s: %s (errno %d)\n",
		     path, strerror (errno), errno);
	else if (S_ISREG (info.st_mode) && now - info.st_ctime >= _24_HOURS)
	{
	    /* this should happen infrequently enough that it won't be
	     * bothersome to the user to display when it occurs.
	     */
	    printf ("Warning: removing stale file %s\n", path);
	    if (unlink (path))
		fprintf (stderr,
			 "maildir_clean_tmp: unlink: %s: %s (errno %d)\n",
			 path, strerror (errno), errno);
	}
    }
    closedir(dirp);
}

void
maildir_close (mailbox_t * mbox)
{
    if (mbox->db)
	dbm_close (mbox->db);

    /* release the mutex on the mailbox */
    dotlock_unlock (&mbox->lockfd);

    /* per the maildir(5) specification, delivery agents are supposed to
     * set a 24-hour timer on items placed in the `tmp' directory.
     */
    maildir_clean_tmp (mbox->path);

    free (mbox->path);
    free_message (mbox->msgs);
    memset (mbox, 0xff, sizeof (mailbox_t));
    free (mbox);
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
