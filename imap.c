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
#if HAVE_LIBSSL
#include <openssl/err.h>
#endif
#include "isync.h"

const char *Flags[] = {
    "\\Seen",
    "\\Answered",
    "\\Deleted",
    "\\Flagged",
    "\\Recent",
    "\\Draft"
};

#if HAVE_LIBSSL
SSL_CTX *SSLContext = 0;

static int
init_ssl (config_t * conf)
{
    if (!conf->cert_file)
    {
	puts ("Error, CertificateFile not defined");
	return -1;
    }
    SSL_library_init ();
    SSL_load_error_strings ();
    SSLContext = SSL_CTX_new (SSLv23_client_method ());
    if (!SSL_CTX_load_verify_locations (SSLContext, conf->cert_file, NULL))
    {
	printf ("Error, SSL_CTX_load_verify_locations: %s\n",
		ERR_error_string (ERR_get_error (), 0));
	return -1;
    }
    SSL_CTX_set_verify (SSLContext,
			SSL_VERIFY_PEER |
			SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
			SSL_VERIFY_CLIENT_ONCE, NULL);
    SSL_CTX_set_verify_depth (SSLContext, 1);
    return 0;
}

#endif

static int
socket_read (Socket_t * sock, char *buf, size_t len)
{
#if HAVE_LIBSSL
    if (sock->use_ssl)
	return SSL_read (sock->ssl, buf, len);
#endif
    return read (sock->fd, buf, len);
}

static int
socket_write (Socket_t * sock, char *buf, size_t len)
{
#if HAVE_LIBSSL
    if (sock->use_ssl)
	return SSL_write (sock->ssl, buf, len);
#endif
    return write (sock->fd, buf, len);
}

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

	    n =
		socket_read (b->sock, b->buf + b->offset,
			     sizeof (b->buf) - b->offset);

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
parse_fetch (imap_t * imap, list_t * list, message_t *cur)
{
    list_t *tmp;

    if (!is_list (list))
	return -1;

    for (tmp = list->child; tmp; tmp = tmp->next)
    {
	if (is_atom (tmp))
	{
	    if (!strcmp ("UID", tmp->val))
	    {
		tmp = tmp->next;
		if (is_atom (tmp))
		    cur->uid = atoi (tmp->val);
		else
		    puts ("Error, unable to parse UID");
	    }
	    else if (!strcmp ("FLAGS", tmp->val))
	    {
		tmp = tmp->next;
		if (is_list (tmp))
		{
		    list_t *flags = tmp->child;

		    for (; flags; flags = flags->next)
		    {
			if (is_atom (flags))
			{
			    if (!strcmp ("\\Seen", flags->val))
				cur->flags |= D_SEEN;
			    else if (!strcmp ("\\Flagged", flags->val))
				cur->flags |= D_FLAGGED;
			    else if (!strcmp ("\\Deleted", flags->val))
			    {
				cur->flags |= D_DELETED;
				imap->deleted++;
			    }
			    else if (!strcmp ("\\Answered", flags->val))
				cur->flags |= D_ANSWERED;
			    else if (!strcmp ("\\Draft", flags->val))
				cur->flags |= D_DRAFT;
			    else if (!strcmp ("\\Recent", flags->val))
				cur->flags |= D_RECENT;
			    else
				printf ("Warning, unknown flag %s\n",flags->val);
			}
			else
			    puts ("Error, unable to parse FLAGS list");
		    }
		}
		else
		    puts ("Error, unable to parse FLAGS");
	    }
	}
    }
    return 0;
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
    socket_write (imap->sock, buf, strlen (buf));

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
	    if (!arg)
	    {
		puts ("Error, unable to parse untagged command");
		return -1;
	    }

	    if (!strcmp ("NAMESPACE", arg))
	    {
		imap->ns_personal = parse_list (cmd, &cmd);
		imap->ns_other = parse_list (cmd, &cmd);
		imap->ns_shared = parse_list (cmd, 0);
	    }
	    else if (!strcmp ("SEARCH", arg))
	    {
		if (!rec)
		{
		    rec = &imap->recent_msgs;
		    while (*rec)
			rec = &(*rec)->next;
		}
		/* parse rest of `cmd' */
		while ((arg = next_arg (&cmd)))
		{
		    *rec = calloc (1, sizeof (message_t));
		    (*rec)->uid = atoi (arg);
		    rec = &(*rec)->next;
		}
	    }
	    else if ((arg1 = next_arg (&cmd)))
	    {
		if (!strcmp ("EXISTS", arg1))
		    imap->count = atoi (arg);
		else if (!strcmp ("RECENT", arg1))
		    imap->recent = atoi (arg);
		else if (!strcmp ("FETCH", arg1))
		{
		    list_t *list;

		    if (!cur)
		    {
			cur = &imap->msgs;
			while (*cur)
			    cur = &(*cur)->next;
		    }

		    list = parse_list (cmd, 0);

		    *cur = calloc (1, sizeof(message_t));
		    if (parse_fetch (imap, list, *cur))
		    {
			free_list (list);
			return -1;
		    }

		    free_list (list);

		    cur = &(*cur)->next;
		}
	    }
	    else
	    {
		puts ("Error, unable to parse untagged command");
		return -1;
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
    char *ns_prefix = 0;
#if HAVE_LIBSSL
    int use_ssl = 0;
#endif

#if HAVE_LIBSSL
    /* initialize SSL */
    if (init_ssl (box))
	return 0;
#endif

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
    imap->sock = calloc (1, sizeof (Socket_t));
    imap->sock->fd = s;
    imap->buf = calloc (1, sizeof (buffer_t));
    imap->buf->sock = imap->sock;
    imap->box = box;

#if HAVE_LIBSSL
    if (!box->use_imaps)
    {
	/* always try to select SSL support if available */
	ret = imap_exec (imap, "STARTTLS");
	if (!ret)
	    use_ssl = 1;
	else if (box->require_ssl)
	{
	    puts ("Error, SSL support not available");
	    return 0;
	}
	else
	    puts ("Warning, SSL support not available");
    }
    else
	use_ssl = 1;

    if (use_ssl)
    {
	imap->sock->ssl = SSL_new (SSLContext);
	SSL_set_fd (imap->sock->ssl, imap->sock->fd);
	ret = SSL_connect (imap->sock->ssl);
	if (ret <= 0)
	{
	    ret = SSL_get_error (imap->sock->ssl, ret);
	    printf ("Error, SSL_connect: %s\n", ERR_error_string (ret, 0));
	    return 0;
	}
	imap->sock->use_ssl = 1;
	puts ("SSL support enabled");
    }
#endif

    puts ("Logging in...");
    ret = imap_exec (imap, "LOGIN %s %s", box->user, box->pass);

    if (!ret)
    {
	/* get NAMESPACE info */
	if (!imap_exec (imap, "NAMESPACE"))
	{
	    /* XXX for now assume personal namespace */
	    if (is_list (imap->ns_personal) &&
		    is_list(imap->ns_personal->child) &&
		    is_atom(imap->ns_personal->child->child))
	    {
		ns_prefix = imap->ns_personal->child->child->val;
	    }
	}
    }

    if (!ret)
    {
	fputs ("Selecting mailbox... ", stdout);
	fflush (stdout);
	ret = imap_exec (imap, "SELECT %s%s",
			 ns_prefix ? ns_prefix : "", box->box);
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
send_server (Socket_t * sock, const char *fmt, ...)
{
    char buf[128];
    char cmd[128];
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);

    snprintf (cmd, sizeof (cmd), "%d %s\r\n", ++Tag, buf);
    socket_write (sock, cmd, strlen (cmd));

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

    send_server (imap->sock, "UID FETCH %d RFC822.PEEK", uid);

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
		n = socket_read (imap->sock, buf, n);
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
