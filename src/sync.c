/* $Id$
 *
 * isync - IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2003 Oswald Buddenhagen <ossi@users.sf.net>
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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

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
set_uid (DB * db, const char *f, unsigned int uid)
{
    char *s;
    DBT key, val;
    int ret;

    memset (&key, 0, sizeof(key));
    memset (&val, 0, sizeof(val));
    key.data = (void *) f;
    s = strchr (f, ':');
    key.size = s ? (size_t) (s - f) : strlen (f);
    val.data = (void *) &uid;
    val.size = sizeof (uid);
    ret = db->put (db, 0, &key, &val, 0);
    if (ret < 0)
	fprintf (stderr, "Unexpected error (%d) from db_put(%.*s, %d)\n", 
		 ret, key.size, f, uid);
    db->sync(db, 0);
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

    if (mbox->uidseen)
    {
	if (mbox->uidvalidity != imap->uidvalidity)
	{
	    /* if the UIDVALIDITY value has changed, it means all our
	     * local UIDs are invalid, so we can't sync.
	     */
	    fprintf (stderr,
		     "ERROR: UIDVALIDITY of '%s' changed on server\n",
		     imap->box->box);
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

		if ((cur->flags & D_DELETED) && (flags & SYNC_EXPUNGE))
		{
		  /*
		   * This message is marked as deleted and we are
		   * expunging.  Don't upload to the server.
		   */
		  continue;
		}

		if (!upload)
		    info ("Uploading messages");
		infoc ('.');
		fflush (stdout);
		upload++;

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
		    info ("Local message %s is too large (%lu), skipping...\n",
			  cur->file, (unsigned long) sb.st_size);
		    continue;
		}
		fd = open (path, O_RDONLY);
		if (fd == -1)
		{
		    /* This can happen if the message was simply deleted (ok)
		       or the flags changed (not ok - maildir sucks). */
		    fprintf (stderr, "Error, unable to open %s: %s (errno %d)\n",
			    path, strerror (errno), errno);
		    continue;
		}

		cur->size = sb.st_size;
		cur->uid = imap_append_message (imap, fd, cur);
		if (cur->uid != (unsigned int) -1) {
		    /* update the db */
		    set_uid (mbox->db, cur->file, cur->uid);
		    if (!cur->uid)
			warn ("Warning: no UID for new messge %s\n", cur->file);
		    else if (cur->uid > mbox->maxuid)
		    	mbox->maxuid = cur->uid;
		}

		close (fd);
	    }
	    /*
	     * message used to exist on server but no longer does (we know
	     * this beacause it has a UID associated with it).
	     */
	    else if (flags & SYNC_DELETE)
	    {
		cur->flags |= D_DELETED;
		cur->dead = 1;
		mbox->deleted++;
	    }
	    /* if the user doesn't want local msgs deleted when they don't
	     * exist on the server, warn that such messages exist.
	     */
	    else
		info ("Local message %u doesn't exist on server\n", cur->uid);
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

	    /* don't bother renaming the file if we are just going to
	     * remove it later.
	     */
	    if ((cur->flags & D_DELETED) == 0 || (flags & SYNC_EXPUNGE) == 0)
	    {
		    size_t sl;

		    /* generate old path */
		    snprintf (path, sizeof (path), "%s/%s/%s",
				    mbox->path, cur->new ? "new" : "cur", cur->file);

		    /* generate new path */
		    strcpy (newpath, path);
		    p = strchr (newpath, ':');
		    sl = p ? (size_t)(p - newpath) : strlen (newpath);
		    snprintf (newpath + sl, sizeof (newpath) - sl, ":2,%s%s%s%s",
				    (cur->flags & D_FLAGGED) ? "F" : "",
				    (cur->flags & D_ANSWERED) ? "R" : "",
				    (cur->flags & D_SEEN) ? "S" : "",
				    (cur->flags & D_DELETED) ? "T" : "");

		    if (rename (path, newpath))
		    {
			    perror ("Warning: cannot set flags on message");
		    }
		    else
		    {
			    /* update the filename in the msg struct */
			    p = strrchr (newpath, '/');
			    free (cur->file);
			    cur->file = strdup (p + 1);
		    }
	    }
	}
    }

    if (upload)
	info (" %d messages.\n", upload);

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
		info ("Remote message %u skipped because it is too big (%u)\n",
		      cur->uid, cur->size);
		continue;
	    }

	    /* construct the flags part of the file name. */

	    *suffix = 0;
	    if (cur->flags & ~(D_RECENT | D_DRAFT))
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

	    /* give some visual feedback that something is happening */
	    if (!fetched)
		info ("Fetching new messages");
	    infoc ('.');
	    fflush (stdout);
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
			  (cur->flags & D_SEEN) ? "cur" : "new", p); /* hack: ignore \recent, use !\seen instead */

		/* its ok if this fails, the next time we sync the message
		 * will get pulled down
		 */
		if (link (path, newpath))
		    perror ("link");
		else
		{
		    /* update the db with the UID mapping for this file */
		    set_uid (mbox->db, p + 1, cur->uid);
		    if (cur->uid > mbox->maxuid)
		    	mbox->maxuid = cur->uid;
		}
	    }

	    /* always remove the temp file */
	    unlink (path);
	}
    }

    if (fetched)
	info (" %d messages\n", fetched);

    if (maildir_update_maxuid (mbox))
	return -1;

    return 0;
}
