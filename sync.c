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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "isync.h"

static unsigned int MaildirCount = 0;

message_t *
find_msg (message_t * list, unsigned int uid)
{
    for (; list; list = list->next)
	if (list->uid == uid)
	    return list;
    return 0;
}

static int
set_uid (DBM * db, const char *f, unsigned int uid)
{
    char *s;
    datum key, val;

    key.dptr = (void *) f;
    s = strchr (f, ':');
    key.dsize = s ? (size_t) (s - key.dptr) : strlen (f);
    val.dptr = (void *) &uid;
    val.dsize = sizeof (uid);
    dbm_store (db, key, val, DBM_REPLACE);
    return 0;
}

int
sync_mailbox (mailbox_t * mbox, imap_t * imap, int flags,
	      unsigned int max_size, unsigned int max_msgs)
{
    message_t *cur;
    message_t *tmp;
    char path[_POSIX_PATH_MAX];
    char newpath[_POSIX_PATH_MAX];
    char suffix[_POSIX_PATH_MAX];
    char *p;
    int fd;
    int ret;
    int fetched = 0;
    int upload = 0;
    unsigned int msg_count;

    if (mbox->uidvalidity > 0)
    {
	if (mbox->uidvalidity != imap->uidvalidity)
	{
	    /* if the UIDVALIDITY value has changed, it means all our
	     * local UIDs are invalid, so we can't sync.
	     */
	    fputs ("ERROR: UIDVALIDITY changed on server (fatal)\n", stderr);
	    return -1;
	}
    }
    else if (maildir_set_uidvalidity (mbox, imap->uidvalidity))
    {
	fputs ("ERROR: unable to store UIDVALIDITY\n", stderr);
	return -1;
    }

    if (mbox->maxuid == 0 || imap->maxuid > mbox->maxuid)
    {
	mbox->maxuid = imap->maxuid;
	if (maildir_update_maxuid (mbox))
	    return -1;
    }

    /* if we are --fast mode, the mailbox wont have been loaded, so
     * this next step is skipped.
     */
    for (cur = mbox->msgs; cur; cur = cur->next)
    {
	tmp = find_msg (imap->msgs, cur->uid);
	if (!tmp)
	{
	    /* if this message wasn't fetched from the server, attempt to
	     * upload it
	     */
	    if (cur->uid == (unsigned int) -1)
	    {
		struct stat sb;

		if ((flags & SYNC_QUIET) == 0)
		{
		    if (!upload)
			fputs ("Uploading messages", stdout);
		    fputc ('.', stdout);
		    fflush (stdout);
		    upload++;
		}

		/* upload the message if its not too big */
		snprintf (path, sizeof (path), "%s/%s/%s", mbox->path,
			  cur->new ? "new" : "cur", cur->file);
		if (stat (path, &sb))
		{
		    perror (path);
		    continue;	/* not fatal */
		}
		if (imap->box->max_size > 0
		    && sb.st_size > imap->box->max_size)
		{
		    if ((flags & SYNC_QUIET) == 0)
			printf
			    ("Warning, local message is too large (%lu), skipping...\n",
			     (unsigned long) sb.st_size);
		    continue;
		}
		fd = open (path, O_RDONLY);
		if (fd == -1)
		{
		    printf ("Error, unable to open %s: %s (errno %d)\n",
			    path, strerror (errno), errno);
		    continue;
		}

		cur->size = sb.st_size;
		cur->uid = imap_append_message (imap, fd, cur);
		/* if the server gave us back a uid, update the db */
		if (cur->uid != (unsigned int) -1)
		    set_uid (mbox->db, cur->file, cur->uid);

		close (fd);
	    }
	    else if (flags & SYNC_DELETE)
	    {
		cur->flags |= D_DELETED;
		cur->dead = 1;
		mbox->deleted++;
	    }
	    /* if the user doesn't want local msgs deleted when they don't
	     * exist on the server, warn that such messages exist.
	     */
	    else if ((flags & SYNC_QUIET) == 0)
		printf ("Warning, uid %u doesn't exist on server\n",
			cur->uid);
	    continue;
	}
	tmp->processed = 1;

	/* if the message is deleted, and CopyDeletedTo is set, and we
	 * are expunging, make a copy of the message now.
	 */
	if (((cur->flags | tmp->flags) & D_DELETED) != 0 &&
	    (flags & SYNC_EXPUNGE) && imap->box->copy_deleted_to)
	{
	    if (imap_copy_message (imap, cur->uid,
				   imap->box->copy_deleted_to))
	    {
		fprintf (stderr,
			 "ERROR: unable to copy deleted message to \"%s\"\n",
			 imap->box->copy_deleted_to);
		return -1;
	    }
	}

	/* check if local flags are different from server flags.
	 * ignore \Recent and \Draft
	 */
	if (cur->flags != (tmp->flags & ~(D_RECENT | D_DRAFT)))
	{
	    /* set local flags that don't exist on the server */
	    if (!(tmp->flags & D_DELETED) && (cur->flags & D_DELETED))
		imap->deleted++;

	    imap_set_flags (imap, cur->uid, cur->flags & ~tmp->flags);

	    /* update local flags */
	    if ((cur->flags & D_DELETED) == 0 && (tmp->flags & D_DELETED))
		mbox->deleted++;
	    cur->flags |= (tmp->flags & ~(D_RECENT | D_DRAFT));

	    /* generate old path */
	    snprintf (path, sizeof (path), "%s/%s/%s",
		      mbox->path, cur->new ? "new" : "cur", cur->file);

	    /* truncate old flags (if present) */
	    p = strchr (cur->file, ':');
	    if (p)
		*p = 0;

	    /* generate new path - always put this in the cur/ directory
	     * because its no longer new
	     */
	    snprintf (newpath, sizeof (newpath), "%s/cur/%s:2,%s%s%s%s",
		      mbox->path,
		      cur->file, (cur->flags & D_FLAGGED) ? "F" : "",
		      (cur->flags & D_ANSWERED) ? "R" : "",
		      (cur->flags & D_SEEN) ? "S" : "",
		      (cur->flags & D_DELETED) ? "T" : "");

	    if (rename (path, newpath))
		perror ("rename");
	}
    }

    if (upload)
	fprintf (stdout, " %d messages.\n", upload);

    if ((flags & SYNC_QUIET) == 0)
    {
	fputs ("Fetching new messages", stdout);
	fflush (stdout);
    }

    if (max_msgs == 0)
	max_msgs = UINT_MAX;
    else
    {
	/* expire messages in excess of the max-count for this mailbox.
	 * flagged mails are considered sacrosant and not deleted.
	 * we have already done the upload to the server, so messing with
	 * the flags variable do not have remote side effects.
	 */
	for (cur = imap->msgs, msg_count = 0;
	     cur && msg_count < max_msgs; cur = cur->next, msg_count++)
	{
	    tmp = find_msg (mbox->msgs, cur->uid);
	    if (tmp)
		tmp->wanted = 1;
	}
	for (cur = mbox->msgs; cur; cur = cur->next)
	{
	    if (!cur->wanted && !(cur->flags & D_FLAGGED))
	    {
		cur->flags |= D_DELETED;
		cur->dead = 1;
		mbox->deleted++;
	    }
	}
    }

    for (cur = imap->msgs, msg_count = 0;
	 cur && msg_count < max_msgs; cur = cur->next, msg_count++)
    {
	if (!cur->processed)
	{
	    /* new message on server */

	    if ((flags & SYNC_EXPUNGE) && (cur->flags & D_DELETED))
	    {
		/* this message has been marked for deletion and
		 * we are currently expunging a mailbox.  don't
		 * bother downloading this message
		 */
		continue;
	    }

	    if (max_size && cur->size > max_size)
	    {
		if ((flags & SYNC_QUIET) == 0)
		    printf
			("Warning, message skipped because it is too big (%u)\n",
			 cur->size);
		continue;
	    }

	    /* construct the flags part of the file name. */

	    *suffix = 0;
	    if (cur->flags & ~D_RECENT)
	    {
		snprintf (suffix, sizeof (suffix), ":2,%s%s%s%s",
			  (cur->flags & D_FLAGGED) ? "F" : "",
			  (cur->flags & D_ANSWERED) ? "R" : "",
			  (cur->flags & D_SEEN) ? "S" : "",
			  (cur->flags & D_DELETED) ? "T" : "");
	    }

	    for (;;)
	    {
		/* create new file */
		snprintf (path, sizeof (path), "%s/tmp/%ld_%d.%d.%s%s",
			  mbox->path, time (0), MaildirCount++, getpid (),
			  Hostname, suffix);

		if ((fd = open (path, O_WRONLY | O_CREAT | O_EXCL, 0600)) > 0)
		    break;
		if (errno != EEXIST)
		{
		    perror (path);
		    break;
		}

		sleep (2);
	    }

	    if (fd < 0)
		continue;

	    if ((flags & SYNC_QUIET) == 0)
	    {
		/* give some visual feedback that something is happening */
		fputs (".", stdout);
		fflush (stdout);
	    }
	    fetched++;

	    ret = imap_fetch_message (imap, cur->uid, fd);

	    if (fsync (fd))
	    {
		perror ("fsync");
		close (fd);
	    }
	    else if (close (fd))
		perror ("close");
	    else if (!ret)
	    {
		p = strrchr (path, '/');

		snprintf (newpath, sizeof (newpath), "%s/%s%s", mbox->path,
			  (cur->flags & ~D_RECENT) ? "cur" : "new", p);

		/* its ok if this fails, the next time we sync the message
		 * will get pulled down
		 */
		if (link (path, newpath))
		    perror ("link");
		else
		{
		    /* update the db with the UID mapping for this file */
		    set_uid (mbox->db, p + 1, cur->uid);
		}
	    }

	    /* always remove the temp file */
	    unlink (path);
	}
    }

    if ((flags & SYNC_QUIET) == 0)
	printf ("  %d messages\n", fetched);

    return 0;
}
