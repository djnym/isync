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

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "isync.h"

const char *Flags[] = {
    "\\Seen",
    "\\Answered",
    "\\Deleted",
    "\\Flagged",
    "\\Recent",
    "\\Draft"
};

/* simple line buffering */
static int
buffer_gets (buffer_t * b, char **s)
{
    int n;
    int start = b->offset;

    *s = b->buf + start;

    for (;;)
    {
	if (b->offset + 2 > b->bytes)
	{
	    /* shift down used bytes */
	    *s = b->buf;

	    assert (start <= b->bytes);
	    n = b->bytes - start;

	    if (n)
		memmove (b->buf, b->buf + start, n);
	    b->offset = n;
	    start = 0;

	    n = read (b->fd, b->buf + b->offset, sizeof (b->buf) - b->offset);
	    if (n <= 0)
	    {
		if (n == -1)
		    perror ("read");
		else
		    puts ("EOF");
		return -1;
	    }
	    b->bytes = b->offset + n;

//          printf ("buffer_gets:read %d bytes\n", n);
	}

	if (b->buf[b->offset] == '\r')
	{
	    if (b->buf[b->offset + 1] == '\n')
	    {
		b->buf[b->offset] = 0;	/* terminate the string */
		b->offset += 2;	/* next line */
		return 0;
	    }
	}

	b->offset++;
    }
    /* not reached */
}

static int
imap_exec (imap_t * imap, const char *fmt, ...)
{
    va_list ap;
    char tmp[256];
    char buf[256];
    char *cmd;
    char *arg;
    char *arg1;
    message_t **cur = 0;
    message_t **rec = 0;

    va_start (ap, fmt);
    vsnprintf (tmp, sizeof (tmp), fmt, ap);
    va_end (ap);

    snprintf (buf, sizeof (buf), "%d %s\r\n", ++Tag, tmp);
    if (Verbose)
	fputs (buf, stdout);
    write (imap->fd, buf, strlen (buf));

    for (;;)
    {
	if (buffer_gets (imap->buf, &cmd))
	    return -1;
	if (Verbose)
	    puts (cmd);

	arg = next_arg (&cmd);
	if (*arg == '*')
	{
	    arg = next_arg (&cmd);
	    arg1 = next_arg (&cmd);

	    if (arg1 && !strcmp ("EXISTS", arg1))
		imap->count = atoi (arg);
	    else if (arg1 && !strcmp ("RECENT", arg1))
		imap->recent = atoi (arg);
	    else if (!strcmp ("SEARCH", arg))
	    {
		if (!rec)
		{
		    rec = &imap->msgs;
		    while (*rec)
			rec = &(*rec)->next;
		}
		while ((arg = next_arg (&cmd)))
		{
		    *rec = calloc (1, sizeof (message_t));
		    (*rec)->uid = atoi (arg);
		    rec = &(*rec)->next;
		}
	    }
	    else if (arg1 && !strcmp ("FETCH", arg1))
	    {
		if (!cur)
		{
		    cur = &imap->msgs;
		    while (*cur)
			cur = &(*cur)->next;
		}

		/* new message
		 *      * <N> FETCH (UID <uid> FLAGS (...))
		 */
		arg = next_arg (&cmd);	/* (UID */
		arg = next_arg (&cmd);	/* <uid> */
		*cur = calloc (1, sizeof (message_t));
		(*cur)->uid = atoi (arg);

		arg = next_arg (&cmd);	/* FLAGS */
		if (!arg || strcmp ("FLAGS", arg))
		{
		    printf ("FETCH parse error: expected FLAGS at %s\n", arg);
		    return -1;
		}

		/* if we need to parse additional info, we should keep
		 * a copy of this `arg' pointer
		 */

		cmd++;
		arg = strchr (cmd, ')');
		if (!arg)
		{
		    puts ("FETCH parse error");
		    return -1;
		}
		*arg = 0;

		/* parse message flags */
		while ((arg = next_arg (&cmd)))
		{
		    if (!strcmp ("\\Seen", arg))
			(*cur)->flags |= D_SEEN;
		    else if (!strcmp ("\\Flagged", arg))
			(*cur)->flags |= D_FLAGGED;
		    else if (!strcmp ("\\Deleted", arg))
			(*cur)->flags |= D_DELETED;
		    else if (!strcmp ("\\Answered", arg))
			(*cur)->flags |= D_ANSWERED;
		    else if (!strcmp ("\\Draft", arg))
			(*cur)->flags |= D_DRAFT;
		    else if (!strcmp ("\\Recent", arg))
			(*cur)->flags |= D_RECENT;
		    else
			printf ("warning, unknown flag %s\n", arg);
		}

		cur = &(*cur)->next;
	    }
	}
	else if ((size_t) atol (arg) != Tag)
	{
	    puts ("wrong tag");
	    return -1;
	}
	else
	{
	    arg = next_arg (&cmd);
	    if (!strcmp ("OK", arg))
		return 0;
	    puts ("IMAP command failed");
	    return -1;
	}
    }
    /* not reached */
}

static int
fetch_recent_flags (imap_t * imap)
{
    char buf[1024];
    message_t **cur = &imap->recent_msgs;
    message_t *tmp;
    unsigned int start = -1;
    unsigned int last = -1;
    int ret = 0;

    buf[0] = 0;
    while (*cur)
    {
	tmp = *cur;

	if (last == (unsigned int) -1)
	{
	    /* init */
	    start = tmp->uid;
	    last = tmp->uid;
	}
	else if (tmp->uid == last + 1)
	    last++;
	else
	{
	    /* out of sequence */
	    if (start == last)
		ret = imap_exec (imap, "UID FETCH %d (UID FLAGS)", start);
	    else
		ret =
		    imap_exec (imap, "UID FETCH %d:%d (UID FLAGS)", start,
			       last);
	    start = tmp->uid;
	    last = tmp->uid;
	}
	free (tmp);
	*cur = (*cur)->next;
    }

    if (start != (unsigned int) -1)
    {
	if (start == last)
	    ret = imap_exec (imap, "UID FETCH %d (UID FLAGS)", start);
	else
	    ret =
		imap_exec (imap, "UID FETCH %d:%d (UID FLAGS)", start, last);
    }

    return ret;
}

imap_t *
imap_open (config_t * box, int fast)
{
    int ret;
    imap_t *imap;
    int s;
    struct sockaddr_in sin;
    struct hostent *he;

    /* open connection to IMAP server */

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (box->port);
    sin.sin_family = AF_INET;

    printf ("Resolving %s... ", box->host);
    fflush (stdout);
    he = gethostbyname (box->host);
    if (!he)
    {
	perror ("gethostbyname");
	return 0;
    }
    puts ("ok");

    sin.sin_addr.s_addr = *((int *) he->h_addr_list[0]);

    s = socket (PF_INET, SOCK_STREAM, 0);

    printf ("Connecting to %s:%hu... ", inet_ntoa (sin.sin_addr),
	    ntohs (sin.sin_port));
    fflush (stdout);
    if (connect (s, (struct sockaddr *) &sin, sizeof (sin)))
    {
	perror ("connect");
	exit (1);
    }
    puts ("ok");

    imap = calloc (1, sizeof (imap_t));
    imap->fd = s;
    //imap->state = imap_state_init;
    imap->buf = calloc (1, sizeof (buffer_t));
    imap->buf->fd = s;
    imap->box = box;

    puts ("Logging in...");
    ret = imap_exec (imap, "LOGIN %s %s", box->user, box->pass);
    if (!ret)
    {
	fputs ("Selecting mailbox... ", stdout);
	fflush (stdout);
	ret = imap_exec (imap, "SELECT %s", box->box);
	if (!ret)
	    printf ("%d messages, %d recent\n", imap->count, imap->recent);
    }

    if (!ret)
    {
	if (fast)
	{
	    if (imap->recent > 0)
	    {
		puts ("Fetching info for recent messages");
		ret = imap_exec (imap, "UID SEARCH RECENT");
		if (!ret)
		    ret = fetch_recent_flags (imap);
	    }
	}
	else if (imap->count > 0)
	{
	    puts ("Reading IMAP mailbox index");
	    ret = imap_exec (imap, "FETCH 1:%d (UID FLAGS)", imap->count);
	}
    }

    if (ret)
    {
	imap_exec (imap, "LOGOUT");
	close (s);
	free (imap->buf);
	free (imap);
	imap = 0;
    }

    return imap;
}

void
imap_close (imap_t * imap)
{
    puts ("Closing IMAP connection");
    imap_exec (imap, "LOGOUT");
}

/* write a buffer stripping all \r bytes */
static int
write_strip (int fd, char *buf, size_t len)
{
    size_t start = 0;
    size_t end = 0;

    while (start < len)
    {
	while (end < len && buf[end] != '\r')
	    end++;
	write (fd, buf + start, end - start);
	end++;
	start = end;
    }
    return 0;
}

static void
send_server (int fd, const char *fmt, ...)
{
    char buf[128];
    char cmd[128];
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);

    snprintf (cmd, sizeof (cmd), "%d %s\r\n", ++Tag, buf);
    write (fd, cmd, strlen (cmd));

    if (Verbose)
	fputs (cmd, stdout);
}

int
imap_fetch_message (imap_t * imap, unsigned int uid, int fd)
{
    char *cmd;
    char *arg;
    size_t bytes;
    size_t n;
    char buf[1024];

    send_server (imap->fd, "UID FETCH %d RFC822.PEEK", uid);

    for (;;)
    {
	if (buffer_gets (imap->buf, &cmd))
	    return -1;

	if (Verbose)
	    puts (cmd);

	if (*cmd == '*')
	{
	    /* need to figure out how long the message is
	     * * <msgno> FETCH (RFC822 {<size>}
	     */

	    next_arg (&cmd);	/* * */
	    next_arg (&cmd);	/* <msgno> */
	    next_arg (&cmd);	/* FETCH */
	    next_arg (&cmd);	/* (RFC822 */
	    arg = next_arg (&cmd);
	    if (*arg != '{')
	    {
		puts ("parse error getting size");
		return -1;
	    }
	    bytes = strtol (arg + 1, 0, 10);
//          printf ("receiving %d byte message\n", bytes);

	    /* dump whats left over in the input buffer */
	    n = imap->buf->bytes - imap->buf->offset;

	    if (n > bytes)
	    {
		/* the entire message fit in the buffer */
		n = bytes;
	    }

	    /* ick.  we have to strip out the \r\n line endings, so
	     * i can't just dump the raw bytes to disk.
	     */
	    write_strip (fd, imap->buf->buf + imap->buf->offset, n);

	    bytes -= n;

//          printf ("wrote %d buffered bytes\n", n);

	    /* mark that we used part of the buffer */
	    imap->buf->offset += n;

	    /* now read the rest of the message */
	    while (bytes > 0)
	    {
		n = bytes;
		if (n > sizeof (buf))
		    n = sizeof (buf);
		n = read (imap->fd, buf, n);
		if (n > 0)
		{
//                  printf("imap_fetch_message:%d:read %d bytes\n", __LINE__, n);
		    write_strip (fd, buf, n);
		    bytes -= n;
		}
		else
		{
		    if (n == (size_t) - 1)
			perror ("read");
		    else
			puts ("EOF");
		    return -1;
		}
	    }

//          puts ("finished fetching msg");

	    buffer_gets (imap->buf, &cmd);
	    if (Verbose)
		puts (cmd);	/* last part of line */
	}
	else
	{
	    arg = next_arg (&cmd);
	    if (!arg || (size_t) atoi (arg) != Tag)
	    {
		puts ("wrong tag");
		return -1;
	    }
	    break;
	}
    }

    return 0;
}

/* add flags to existing flags */
int
imap_set_flags (imap_t * imap, unsigned int uid, unsigned int flags)
{
    char buf[256];
    int i;

    buf[0] = 0;
    for (i = 0; i < D_MAX; i++)
    {
	if (flags & (1 << i))
	    snprintf (buf + strlen (buf),
		      sizeof (buf) - strlen (buf), "%s%s",
		      (buf[0] != 0) ? " " : "", Flags[i]);
    }

    return imap_exec (imap, "UID STORE %d +FLAGS.SILENT (%s)", uid, buf);
}

int
imap_expunge (imap_t * imap)
{
    return imap_exec (imap, "EXPUNGE");
}
