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

void
free_message (message_t * msg)
{
    message_t *tmp;

    while (msg)
    {
	tmp = msg;
	msg = msg->next;
	if (tmp->file)
	    free (tmp->file);
	free (tmp);
    }
}

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
    SSL_METHOD *method;
    int options = 0;

    if (!conf->cert_file)
    {
	puts ("Error, CertificateFile not defined");
	return -1;
    }
    SSL_library_init ();
    SSL_load_error_strings ();

    if (conf->use_tlsv1 && !conf->use_sslv2 && !conf->use_sslv3)
	method = TLSv1_client_method ();
    else
	method = SSLv23_client_method ();

    SSLContext = SSL_CTX_new (method);

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
	options |= SSL_OP_NO_SSLv2;
    if (!conf->use_sslv3)
	options |= SSL_OP_NO_SSLv3;
    if (!conf->use_tlsv1)
	options |= SSL_OP_NO_TLSv1;

    SSL_CTX_set_options (SSLContext, options);

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

static void
socket_perror (const char *func, Socket_t *sock, int ret)
{
#if HAVE_LIBSSL
    int err;

    if (sock->use_ssl)
    {
	switch ((err = SSL_get_error (sock->ssl, ret)))
	{
	    case SSL_ERROR_SYSCALL:
	    case SSL_ERROR_SSL:
		if ((err = ERR_get_error ()) == 0)
		{
		    if (ret == 0)
			fprintf (stderr, "SSL_%s:got EOF\n", func);
		    else
			fprintf (stderr, "SSL_%s:%d:%s\n", func,
				errno, strerror (errno));
		}
		else
		    fprintf (stderr, "SSL_%s:%d:%s\n", func, err,
			    ERR_error_string (err, 0));
		return;
	    default:
		fprintf (stderr, "SSL_%s:%d:unhandled SSL error\n", func, err);
		break;
	}
	return;
    }
#else
    (void) sock;
#endif
    if (ret)
      perror (func);
    else
      fprintf (stderr, "%s: unexpected EOF\n", func);
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
		socket_perror ("read", b->sock, n);
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
    int n;

    va_start (ap, fmt);
    vsnprintf (tmp, sizeof (tmp), fmt, ap);
    va_end (ap);

    snprintf (buf, sizeof (buf), "%d %s\r\n", ++Tag, tmp);
    if (Verbose)
    {
	fputs (">>> ", stdout);
	fputs (buf, stdout);
    }
    n = socket_write (imap->sock, buf, strlen (buf));
    if (n <= 0)
    {
	socket_perror ("write", imap->sock, n);
	return -1;
    }

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
		     !strcmp ("NO", arg) || !strcmp ("BYE", arg) ||
		     !strcmp ("PREAUTH", arg))
	    {
		parse_response_code (imap, cmd);
	    }
	    else if (!strcmp ("CAPABILITY", arg))
	    {
#if HAVE_LIBSSL
		while ((arg = next_arg (&cmd)))
		{
		    if (!strcmp ("STARTTLS", arg))
			imap->have_starttls = 1;
		    else if (!strcmp ("AUTH=CRAM-MD5", arg))
			imap->have_cram = 1;
		    else if (!strcmp ("NAMESPACE", arg))
			imap->have_namespace = 1;
		}
#endif
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
#if HAVE_LIBSSL
	else if (*arg == '+')
	{
	    char *resp;

	    if (!imap->cram)
	    {
		puts ("Error, not doing CRAM-MD5 authentication");
		return -1;
	    }
	    resp = cram (cmd, imap->box->user, imap->box->pass);

	    n = socket_write (imap->sock, resp, strlen (resp));
	    if (n <= 0)
	    {
		socket_perror ("write", imap->sock, n);
		return -1;
	    }
	    if (Verbose)
		puts (resp);
	    n = socket_write (imap->sock, "\r\n", 2);
	    if (n <= 0)
	    {
		socket_perror ("write", imap->sock, n);
		return -1;
	    }
	    free (resp);
	    imap->cram = 0;
	}
#endif
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
imap_open (config_t * box, unsigned int minuid, imap_t * imap, int flags)
{
  int ret;
  int s;
  struct sockaddr_in addr;
  struct hostent *he;
  char *arg, *rsp;
  int reuse = 0;
  int preauth = 0;
#if HAVE_LIBSSL
  int use_ssl = 0;
#endif

  (void) flags;

  if (imap)
  {
    /* determine whether or not we can reuse the existing session */
    if (strcmp (box->host, imap->box->host) ||
	strcmp (box->user, imap->box->user) ||
	box->port != imap->box->port
#if HAVE_LIBSSL
	/* ensure that security requirements are met */
	|| (box->require_ssl ^ imap->box->require_ssl)
	|| (box->require_cram ^ imap->box->require_cram)
#endif
       )
    {
      /* can't reuse */
      imap_close (imap);
      imap = 0;
    }
    else
    {
      reuse = 1;
      /* reset mailbox-specific state info */
      imap->recent = 0;
      imap->deleted = 0;
      imap->count = 0;
      imap->maxuid = 0;
      free_message (imap->msgs);
      imap->msgs = 0;
    }
  }

  if (!imap)
  {
    imap = calloc (1, sizeof (imap_t));
    imap->sock = calloc (1, sizeof (Socket_t));
    imap->buf = calloc (1, sizeof (buffer_t));
    imap->buf->sock = imap->sock;
    imap->sock->fd = -1;
  }

  imap->box = box;
  imap->minuid = minuid;
  imap->prefix = "";

  if (!reuse)
  {
    int a[2];

    /* open connection to IMAP server */

    if (box->tunnel)
    {
      printf ("Starting tunnel '%s'...", box->tunnel);
      fflush (stdout);

      if (socketpair (PF_UNIX, SOCK_STREAM, 0, a))
      {
	perror ("socketpair");
	exit (1);
      }

      if (fork () == 0)
      {
	if (dup2 (a[0],0) || dup2 (a[0], 1))
	{
	  _exit(127);
	}
	close (a[1]);
	execl ("/bin/sh", "sh", "-c", box->tunnel);
	_exit (127);
      }

      close (a[0]);

      imap->sock->fd = a[1];

      puts ("ok");
    }
    else
    {
      memset (&addr, 0, sizeof (addr));
      addr.sin_port = htons (box->port);
      addr.sin_family = AF_INET;

      printf ("Resolving %s... ", box->host);
      fflush (stdout);
      he = gethostbyname (box->host);
      if (!he)
      {
	perror ("gethostbyname");
	return 0;
      }
      puts ("ok");

      addr.sin_addr.s_addr = *((int *) he->h_addr_list[0]);

      s = socket (PF_INET, SOCK_STREAM, 0);

      printf ("Connecting to %s:%hu... ", inet_ntoa (addr.sin_addr),
	      ntohs (addr.sin_port));
      fflush (stdout);
      if (connect (s, (struct sockaddr *) &addr, sizeof (addr)))
      {
	perror ("connect");
	exit (1);
      }
      puts ("ok");

      imap->sock->fd = s;
    }
  }

  do
  {
    /* read the greeting string */
    if (buffer_gets (imap->buf, &rsp))
    {
      puts ("Error, no greeting response");
      ret = -1;
      break;
    }
    if (Verbose)
      puts (rsp);
    arg = next_arg (&rsp);
    if (!arg || *arg != '*' || (arg = next_arg (&rsp)) == NULL)
    {
      puts ("Error, invalid greeting response");
      ret = -1;
      break;
    }
    if (!strcmp ("PREAUTH", arg))
      preauth = 1;
    else if (strcmp ("OK", arg) != 0)
    {
      puts ("Error, unknown greeting response");
      ret = -1;
      break;
    }

    /* if we are reusing the existing connection, we can skip the
     * authentication steps.
     */
    if (!reuse)
    {
#if HAVE_LIBSSL
      if (box->use_imaps)
	use_ssl = 1;
      else
      {
	/* let's see what this puppy can do... */
	if ((ret = imap_exec (imap, "CAPABILITY")))
	  break;

	if (box->use_sslv2 || box->use_sslv3 || box->use_tlsv1)
	{
	  /* always try to select SSL support if available */
	  if (imap->have_starttls)
	  {
	    if ((ret = imap_exec (imap, "STARTTLS")))
	      break;
	    use_ssl = 1;
	  }
	}
      }

      if (!use_ssl)
      {
	if (box->require_ssl)
	{
	  puts ("Error, SSL support not available");
	  ret = -1;
	  break;
	}
	else if (box->use_sslv2 || box->use_sslv3 || box->use_tlsv1)
	  puts ("Warning, SSL support not available");
      }
      else
      {
	/* initialize SSL */
	if (init_ssl (box))
	{
	  ret = -1;
	  break;
	}

	imap->sock->ssl = SSL_new (SSLContext);
	SSL_set_fd (imap->sock->ssl, imap->sock->fd);
	ret = SSL_connect (imap->sock->ssl);
	if (ret <= 0)
	{
	  socket_perror ("connect", imap->sock, ret);
	  break;
	}

	/* verify the server certificate */
	if ((ret = verify_cert (imap->sock->ssl)))
	  break;

	/* to conform to RFC2595 we need to forget all information
	 * retrieved from CAPABILITY invocations before STARTTLS.
	 */
	imap->have_namespace = 0;
	imap->have_cram = 0;
	imap->have_starttls = 0;

	imap->sock->use_ssl = 1;
	puts ("SSL support enabled");

	if ((ret = imap_exec (imap, "CAPABILITY")))
	  break;
      }
#else
      if ((ret = imap_exec (imap, "CAPABILITY")))
	break;
#endif

      if (!preauth)
      {
	puts ("Logging in...");

	if (!box->pass)
	{
	  /*
	   * if we don't have a global password set, prompt the user for
	   * it now.
	   */
	  if (!global.pass)
	  {
	    global.pass = getpass ("Password:");
	    if (!global.pass)
	    {
	      fprintf (stderr, "Skipping %s, no password", box->path);
	      break;
	    }
	  }
	  box->pass = strdup (global.pass);
	}

#if HAVE_LIBSSL
	if (imap->have_cram)
	{
	  puts ("Authenticating with CRAM-MD5");
	  imap->cram = 1;
	  if ((ret = imap_exec (imap, "AUTHENTICATE CRAM-MD5")))
	    break;
	}
	else if (imap->box->require_cram)
	{
	  puts
	    ("Error, CRAM-MD5 authentication is not supported by server");
	  ret = -1;
	  break;
	}
	else
#endif
	{
#if HAVE_LIBSSL
	  if (!use_ssl)
#endif
	    puts
	      ("*** Warning *** Password is being sent in the clear");
	  if (
	      (ret =
	       imap_exec (imap, "LOGIN \"%s\" \"%s\"", box->user,
			  box->pass)))
	  {
	    puts ("Error, LOGIN failed");
	    break;
	  }
	}
      }

      /* get NAMESPACE info */
      if (box->use_namespace && imap->have_namespace)
      {
	if ((ret = imap_exec (imap, "NAMESPACE")))
	  break;
      }
    }			/* !reuse */

    /* XXX for now assume personal namespace */
    if (imap->box->use_namespace && is_list (imap->ns_personal) &&
	is_list (imap->ns_personal->child) &&
	is_atom (imap->ns_personal->child->child))
    {
      imap->prefix = imap->ns_personal->child->child->val;
    }

    fputs ("Selecting mailbox... ", stdout);
    fflush (stdout);
    if ((ret = imap_exec (imap, "SELECT \"%s%s\"", imap->prefix, box->box)))
      break;
    printf ("%d messages, %d recent\n", imap->count, imap->recent);

    puts ("Reading IMAP mailbox index");
    if (imap->count > 0)
    {
      if ((ret = imap_exec (imap, "UID FETCH %d:* (FLAGS RFC822.SIZE)",
			    imap->minuid)))
	break;
    }
  }
  while (0);

  if (ret)
  {
    imap_close (imap);
    imap = 0;
  }

  return imap;
}

void
imap_close (imap_t * imap)
{
  if (imap)
  {
    imap_exec (imap, "LOGOUT");
    close (imap->sock->fd);
    free (imap->sock);
    free (imap->buf);
    free_message (imap->msgs);
    memset (imap, 0xff, sizeof (imap_t));
    free (imap);
  }
}

/* write a buffer stripping all \r bytes */
static int
write_strip (int fd, char *buf, size_t len)
{
  size_t start = 0;
  size_t end = 0;
  ssize_t n;

  while (start < len)
  {
    while (end < len && buf[end] != '\r')
      end++;
    n = write (fd, buf + start, end - start);
    if (n == -1)
    {
      perror ("write");
      return -1;
    }
    else if ((size_t) n != end - start)
    {
      /* short write, try again */
      start += n;
    }
    else
    {
      /* write complete */
      end++;
      start = end;
    }
  }
  return 0;
}

static int
send_server (Socket_t * sock, const char *fmt, ...)
{
  char buf[128];
  char cmd[128];
  va_list ap;
  int n;

  va_start (ap, fmt);
  vsnprintf (buf, sizeof (buf), fmt, ap);
  va_end (ap);

  snprintf (cmd, sizeof (cmd), "%d %s\r\n", ++Tag, buf);
  n = socket_write (sock, cmd, strlen (cmd));
  if (n <= 0)
  {
    socket_perror ("write", sock, n);
    return -1;
  }

  if (Verbose)
    fputs (cmd, stdout);

  return 0;
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
      arg = next_arg (&cmd);	/* FETCH */

      if (strcasecmp ("FETCH", arg) != 0)
      {
	/* this is likely an untagged response, such as when new
	 * mail arrives in the middle of the session.  just skip
	 * it for now.
	 * 
	 * eg.,
	 * "* 4000 EXISTS"
	 * "* 2 RECENT"
	 *
	 */
	printf ("skipping untagged response: %s\n", arg);
	continue;
      }

      while ((arg = next_arg (&cmd)) && *arg != '{')
	;
      if (!arg)
      {
	puts ("parse error getting size");
	return -1;
      }
      bytes = strtol (arg + 1, 0, 10);

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
      if (write_strip (fd, imap->buf->buf + imap->buf->offset, n))
      {
	/* write failed, message is not delivered */
	return -1;
      }

      bytes -= n;

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
	  if (write_strip (fd, buf, n))
	  {
	    /* write failed */
	    return -1;
	  }
	  bytes -= n;
	}
	else
	{
	  socket_perror ("read", imap->sock, n);
	  return -1;
	}
      }

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

int
imap_copy_message (imap_t * imap, unsigned int uid, const char *mailbox)
{
  return imap_exec (imap, "UID COPY %u \"%s%s\"", uid, imap->prefix,
		    mailbox);
}

int
imap_append_message (imap_t * imap, int fd, message_t * msg)
{
  char buf[1024];
  size_t len;
  size_t sofar = 0;
  int lines = 0;
  char flagstr[128];
  char *s;
  size_t i;
  size_t start, end;
  char *arg;

  /* ugh, we need to count the number of newlines */
  while (sofar < msg->size)
  {
    len = msg->size - sofar;
    if (len > sizeof (buf))
      len = sizeof (buf);
    len = read (fd, buf, len);
    if (len == (size_t) - 1)
    {
      perror ("read");
      return -1;
    }
    for (i = 0; i < len; i++)
      if (buf[i] == '\n')
	lines++;
    sofar += len;
  }

  flagstr[0] = 0;
  if (msg->flags)
  {
    strcpy (flagstr, "(");
    if (msg->flags & D_DELETED)
      snprintf (flagstr + strlen (flagstr),
		sizeof (flagstr) - strlen (flagstr), "%s\\Deleted",
		flagstr[1] ? " " : "");
    if (msg->flags & D_ANSWERED)
      snprintf (flagstr + strlen (flagstr),
		sizeof (flagstr) - strlen (flagstr), "%s\\Answered",
		flagstr[1] ? " " : "");
    if (msg->flags & D_SEEN)
      snprintf (flagstr + strlen (flagstr),
		sizeof (flagstr) - strlen (flagstr), "%s\\Seen",
		flagstr[1] ? " " : "");
    if (msg->flags & D_FLAGGED)
      snprintf (flagstr + strlen (flagstr),
		sizeof (flagstr) - strlen (flagstr), "%s\\Flagged",
		flagstr[1] ? " " : "");
    if (msg->flags & D_DRAFT)
      snprintf (flagstr + strlen (flagstr),
		sizeof (flagstr) - strlen (flagstr), "%s\\Draft",
		flagstr[1] ? " " : "");
    snprintf (flagstr + strlen (flagstr),
	      sizeof (flagstr) - strlen (flagstr), ") ");
  }

  send_server (imap->sock, "APPEND %s%s %s{%d}",
	       imap->prefix, imap->box->box, flagstr, msg->size + lines);

  if (buffer_gets (imap->buf, &s))
    return -1;
  if (Verbose)
    puts (s);

  if (*s != '+')
  {
    puts ("Error, expected `+' from server (aborting)");
    return -1;
  }

  /* rewind */
  lseek (fd, 0, 0);

  sofar = 0;
  while (sofar < msg->size)
  {
    len = msg->size - sofar;
    if (len > sizeof (buf))
      len = sizeof (buf);
    len = read (fd, buf, len);
    if (len == (size_t) - 1)
      return -1;
    start = 0;
    while (start < len)
    {
      end = start;
      while (end < len && buf[end] != '\n')
	end++;
      if (start != end)
	socket_write (imap->sock, buf + start, end - start);
      /* only send a crlf if we actually hit the end of a line.  we
       * might be in the middle of a line in which case we don't
       * send one.
       */
      if (end != len)
	socket_write (imap->sock, "\r\n", 2);
      start = end + 1;
    }
    sofar += len;
  }
  socket_write (imap->sock, "\r\n", 2);

  for (;;)
  {
    if (buffer_gets (imap->buf, &s))
      return -1;

    if (Verbose)
      puts (s);

    arg = next_arg (&s);
    if (*arg == '*')
    {
      /* XXX just ignore it for now */
    }
    else if (atoi (arg) != (int) Tag)
    {
      puts ("wrong tag");
      return -1;
    }
    else
    {
      int uid;

      arg = next_arg (&s);
      if (strcmp (arg, "OK"))
	return -1;
      arg = next_arg (&s);
      if (*arg != '[')
	break;
      arg++;
      if (strcasecmp ("APPENDUID", arg))
      {
	puts ("Error, expected APPENDUID");
	break;
      }
      arg = next_arg (&s);
      if (!arg)
	break;
      if (atoi (arg) != (int) imap->uidvalidity)
      {
	puts ("Error, UIDVALIDITY doesn't match APPENDUID");
	return -1;
      }
      arg = next_arg (&s);
      if (!arg)
	break;
      uid = strtol (arg, &s, 10);
      if (*s != ']')
      {
	/* parse error */
	break;
      }
      return uid;
    }
  }

  return 0;
}
