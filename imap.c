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

#define MAX_DEPTH 1

SSL_CTX *SSLContext = 0;

/* this gets called when a certificate is to be verified */
static int
verify_cert (SSL * ssl)
{
    X509 *cert;
    int err;
    char buf[256];
    int ret = -1;
    BIO *bio;

    cert = SSL_get_peer_certificate (ssl);
    if (!cert)
    {
	puts ("Error, no server certificate");
	return -1;
    }

    err = SSL_get_verify_result (ssl);
    if (err == X509_V_OK)
	return 0;

    printf ("Error, can't verify certificate: %s (%d)\n",
	    X509_verify_cert_error_string (err), err);

    X509_NAME_oneline (X509_get_subject_name (cert), buf, sizeof (buf));
    printf ("\nSubject: %s\n", buf);
    X509_NAME_oneline (X509_get_issuer_name (cert), buf, sizeof (buf));
    printf ("Issuer:  %s\n", buf);
    bio = BIO_new (BIO_s_mem ());
    ASN1_TIME_print (bio, X509_get_notBefore (cert));
    memset (buf, 0, sizeof (buf));
    BIO_read (bio, buf, sizeof (buf) - 1);
    printf ("Valid from: %s\n", buf);
    ASN1_TIME_print (bio, X509_get_notAfter (cert));
    memset (buf, 0, sizeof (buf));
    BIO_read (bio, buf, sizeof (buf) - 1);
    BIO_free (bio);
    printf ("      to:   %s\n", buf);

    printf
	("\n*** WARNING ***  There is no way to verify this certificate.  It is\n"
	 "                 possible that a hostile attacker has replaced the\n"
	 "                 server certificate.  Continue at your own risk!\n");
    printf ("\nAccept this certificate anyway? [no]: ");
    fflush (stdout);
    if (fgets (buf, sizeof (buf), stdin) && (buf[0] == 'y' || buf[0] == 'Y'))
    {
	ret = 0;
	puts ("\n*** Fine, but don't say I didn't warn you!\n");
    }
    return ret;

}

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
    if (access (conf->cert_file, F_OK))
    {
	if (errno != ENOENT)
	{
	    perror ("access");
	    return -1;
	}
	puts
	    ("*** Warning, CertificateFile doesn't exist, can't verify server certificates");
    }
    else
	if (!SSL_CTX_load_verify_locations
	    (SSLContext, conf->cert_file, NULL))
    {
	printf ("Error, SSL_CTX_load_verify_locations: %s\n",
		ERR_error_string (ERR_get_error (), 0));
	return -1;
    }

    if (!conf->use_sslv2)
	SSL_CTX_set_options (SSLContext, SSL_OP_NO_SSLv2);
    if (!conf->use_sslv3)
	SSL_CTX_set_options (SSLContext, SSL_OP_NO_SSLv3);
    if (!conf->use_tlsv1)
	SSL_CTX_set_options (SSLContext, SSL_OP_NO_TLSv1);

    /* we check the result of the verification after SSL_connect() */
    SSL_CTX_set_verify (SSLContext, SSL_VERIFY_NONE, 0);
    return 0;
}
#endif /* HAVE_LIBSSL */

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
	/* make sure we have enough data to read the \r\n sequence */
	if (b->offset + 1 >= b->bytes)
	{
	    if (start != 0)
	    {
		/* shift down used bytes */
		*s = b->buf;

		assert (start <= b->bytes);
		n = b->bytes - start;

		if (n)
		    memmove (b->buf, b->buf + start, n);
		b->offset -= start;
		b->bytes = n;
		start = 0;
	    }

	    n =
		socket_read (b->sock, b->buf + b->bytes,
			     sizeof (b->buf) - b->bytes);

	    if (n <= 0)
	    {
		if (n == -1)
		    perror ("read");
		else
		    puts ("EOF");
		return -1;
	    }

	    b->bytes += n;
	}

	if (b->buf[b->offset] == '\r')
	{
	    assert (b->offset + 1 < b->bytes);
	    if (b->buf[b->offset + 1] == '\n')
	    {
		b->buf[b->offset] = 0;	/* terminate the string */
		b->offset += 2;	/* next line */
//              assert (strchr (*s, '\r') == 0);
		return 0;
	    }
	}

	b->offset++;
    }
    /* not reached */
}

static int
parse_fetch (imap_t * imap, list_t * list)
{
    list_t *tmp;
    unsigned int uid = 0;
    unsigned int mask = 0;
    unsigned int size = 0;
    message_t *cur;

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
		{
		    uid = atoi (tmp->val);
		    if (uid < imap->minuid)
		    {
			/* already saw this message */
			return 0;
		    }
		    else if (uid > imap->maxuid)
			imap->maxuid = uid;
		}
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
				mask |= D_SEEN;
			    else if (!strcmp ("\\Flagged", flags->val))
				mask |= D_FLAGGED;
			    else if (!strcmp ("\\Deleted", flags->val))
				mask |= D_DELETED;
			    else if (!strcmp ("\\Answered", flags->val))
				mask |= D_ANSWERED;
			    else if (!strcmp ("\\Draft", flags->val))
				mask |= D_DRAFT;
			    else if (!strcmp ("\\Recent", flags->val))
				mask |= D_RECENT;
			    else
				printf ("Warning, unknown flag %s\n",
					flags->val);
			}
			else
			    puts ("Error, unable to parse FLAGS list");
		    }
		}
		else
		    puts ("Error, unable to parse FLAGS");
	    }
	    else if (!strcmp ("RFC822.SIZE", tmp->val))
	    {
		tmp = tmp->next;
		if (is_atom (tmp))
		    size = atol (tmp->val);
	    }
	}
    }

#if 0
    if (uid == 221)
    {
	int loop = 1;

	while (loop);
    }
#endif

    cur = calloc (1, sizeof (message_t));
    cur->next = imap->msgs;
    imap->msgs = cur;

    if (mask & D_DELETED)
	imap->deleted++;

    cur->uid = uid;
    cur->flags = mask;
    cur->size = size;

    return 0;
}

static void
parse_response_code (imap_t * imap, char *s)
{
    char *arg;

    if (*s != '[')
	return;			/* no response code */
    s++;

    arg = next_arg (&s);

    if (!strcmp ("UIDVALIDITY", arg))
    {
	arg = next_arg (&s);
	imap->uidvalidity = atol (arg);
    }
    else if (!strcmp ("ALERT", arg))
    {
	/* RFC2060 says that these messages MUST be displayed
	 * to the user
	 */
	fputs ("***ALERT*** ", stdout);
	puts (s);
    }
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
	    else if (!strcmp ("OK", arg) || !strcmp ("BAD", arg) ||
		     !strcmp ("NO", arg) || !strcmp ("PREAUTH", arg) ||
		     !strcmp ("BYE", arg))
	    {
		parse_response_code (imap, cmd);
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

		    list = parse_list (cmd, 0);

		    if (parse_fetch (imap, list))
		    {
			free_list (list);
			return -1;
		    }

		    free_list (list);
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
	    parse_response_code (imap, cmd);
	    if (!strcmp ("OK", arg))
		return 0;
	    return -1;
	}
    }
    /* not reached */
}

/* `box' is the config info for the maildrop to sync.  `minuid' is the
 * minimum UID to consider.  in normal mode this will be 1, but in --fast
 * mode we only fetch messages newer than the last one seen in the local
 * mailbox.
 */
imap_t *
imap_open (config_t * box, unsigned int minuid)
{
    int ret;
    imap_t *imap;
    int s;
    struct sockaddr_in sin;
    struct hostent *he;
    char *ns_prefix = "";
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
    imap->minuid = minuid;

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

	/* verify the server certificate */
	if (verify_cert (imap->sock->ssl))
	    return 0;

	imap->sock->use_ssl = 1;
	puts ("SSL support enabled");
    }
#endif

    puts ("Logging in...");
    ret = imap_exec (imap, "LOGIN \"%s\" \"%s\"", box->user, box->pass);

    if (!ret)
    {
	/* get NAMESPACE info */
	if (box->use_namespace && !imap_exec (imap, "NAMESPACE"))
	{
	    /* XXX for now assume personal namespace */
	    if (is_list (imap->ns_personal) &&
		is_list (imap->ns_personal->child) &&
		is_atom (imap->ns_personal->child->child))
	    {
		ns_prefix = imap->ns_personal->child->child->val;
	    }
	}
    }

    if (!ret)
    {
	fputs ("Selecting mailbox... ", stdout);
	fflush (stdout);
	ret = imap_exec (imap, "SELECT %s%s", ns_prefix, box->box);
	if (!ret)
	    printf ("%d messages, %d recent\n", imap->count, imap->recent);
    }

    if (!ret)
    {
	puts ("Reading IMAP mailbox index");
	if (imap->count > 0)
	{
	    ret = imap_exec (imap, "UID FETCH %d:* (FLAGS RFC822.SIZE)",
			     imap->minuid);
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

    send_server (imap->sock, "UID FETCH %d BODY.PEEK[]", uid);

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

	    while ((arg = next_arg (&cmd)) && *arg != '{')
		;
	    if (!arg)
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
	    arg = next_arg (&cmd);
	    if (!strcmp ("OK", arg))
		return 0;
	    return -1;
	}
    }
    /* not reached */
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
