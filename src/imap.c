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

#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
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
	fprintf (stderr, "Error, no server certificate\n");
	return -1;
    }

    err = SSL_get_verify_result (ssl);
    if (err == X509_V_OK)
	return 0;

    fprintf (stderr, "Error, can't verify certificate: %s (%d)\n",
	     X509_verify_cert_error_string (err), err);

    X509_NAME_oneline (X509_get_subject_name (cert), buf, sizeof (buf));
    info ("\nSubject: %s\n", buf);
    X509_NAME_oneline (X509_get_issuer_name (cert), buf, sizeof (buf));
    info ("Issuer:  %s\n", buf);
    bio = BIO_new (BIO_s_mem ());
    ASN1_TIME_print (bio, X509_get_notBefore (cert));
    memset (buf, 0, sizeof (buf));
    BIO_read (bio, buf, sizeof (buf) - 1);
    info ("Valid from: %s\n", buf);
    ASN1_TIME_print (bio, X509_get_notAfter (cert));
    memset (buf, 0, sizeof (buf));
    BIO_read (bio, buf, sizeof (buf) - 1);
    BIO_free (bio);
    info ("      to:   %s\n", buf);

    fprintf (stderr, 
	"\n*** WARNING ***  There is no way to verify this certificate.  It is\n"
	 "                 possible that a hostile attacker has replaced the\n"
	 "                 server certificate.  Continue at your own risk!\n"
         "\nAccept this certificate anyway? [no]: ");
    if (fgets (buf, sizeof (buf), stdin) && (buf[0] == 'y' || buf[0] == 'Y'))
    {
	ret = 0;
	fprintf (stderr, "\n*** Fine, but don't say I didn't warn you!\n\n");
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
	fprintf (stderr, "Error, CertificateFile not defined\n");
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
	fprintf (stderr, 
	    "*** Warning, CertificateFile doesn't exist, can't verify server certificates\n");
    }
    else
	if (!SSL_CTX_load_verify_locations
	    (SSLContext, conf->cert_file, NULL))
    {
	fprintf (stderr, "Error, SSL_CTX_load_verify_locations: %s\n",
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
		if (Verbose) {
		    puts (*s);
		    fflush (stdout);
		}
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
		    fprintf (stderr, "IMAP error: unable to parse UID\n");
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
				fprintf (stderr, "IMAP error: unknown flag %s\n",
					flags->val);
			}
			else
			    fprintf (stderr, "IMAP error: unable to parse FLAGS list\n");
		    }
		}
		else
		    fprintf (stderr, "IMAP error: unable to parse FLAGS\n");
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
	fprintf (stderr, "*** IMAP ALERT *** %s\n", s);
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
    config_t *box;
    int n;

    va_start (ap, fmt);
    vsnprintf (tmp, sizeof (tmp), fmt, ap);
    va_end (ap);

    snprintf (buf, sizeof (buf), "%d %s\r\n", ++Tag, tmp);
    if (Verbose) {
	printf (">>> %s", buf);
	fflush (stdout);
    }
    n = socket_write (imap->sock, buf, strlen (buf));
    if (n <= 0)
    {
	socket_perror ("write", imap->sock, n);
	return -1;
    }

    for (;;)
    {
      next:
	if (buffer_gets (imap->buf, &cmd))
	    return -1;

	arg = next_arg (&cmd);
	if (*arg == '*')
	{
	    arg = next_arg (&cmd);
	    if (!arg)
	    {
		fprintf (stderr, "IMAP error: unable to parse untagged response\n");
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
		while ((arg = next_arg (&cmd)))
		{
		    if (!strcmp ("UIDPLUS", arg))
			imap->have_uidplus = 1;
		    else if (!strcmp ("NAMESPACE", arg))
			imap->have_namespace = 1;
#if HAVE_LIBSSL
		    else if (!strcmp ("STARTTLS", arg))
			imap->have_starttls = 1;
		    else if (!strcmp ("AUTH=CRAM-MD5", arg))
			imap->have_cram = 1;
#endif
		}
	    }
	    else if (!strcmp ("LIST", arg))
	    {
		list_t *list, *lp;
		int l;

		list = parse_list (cmd, &cmd);
		if (list->val == LIST)
		    for (lp = list->child; lp; lp = lp->next)
			if (is_atom (lp) &&
			    !strcasecmp (lp->val, "\\NoSelect"))
			{
			    free_list (list);
			    goto next;
			}
		free_list (list);
		(void) next_arg (&cmd);	/* skip delimiter */
		arg = next_arg (&cmd);
		l = strlen (global.folder);
		if (memcmp (arg, global.folder, l))
		    goto next;
		arg += l;
		if (!memcmp (arg + strlen (arg) - 5, ".lock", 5))
		    goto next;
		for (box = boxes; box; box = box->next)
		    if (!strcmp (box->box, arg))
			goto next;
		box = malloc (sizeof (config_t));
		memcpy (box, &global, sizeof (config_t));
		box->path = strdup (arg);
		box->box = box->path;
		box->next = boxes;
		boxes = box;
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
		fprintf (stderr, "IMAP error: unable to parse untagged response\n");
		return -1;
	    }
	}
#if HAVE_LIBSSL
	else if (*arg == '+')
	{
	    char *resp;

	    if (!imap->cram)
	    {
		fprintf (stderr, "IMAP error, not doing CRAM-MD5 authentication\n");
		return -1;
	    }
	    resp = cram (cmd, imap->box->user, imap->box->pass);

	    if (Verbose) {
		printf (">+> %s\n", resp);
		fflush (stdout);
	    }
	    n = socket_write (imap->sock, resp, strlen (resp));
	    free (resp);
	    if (n <= 0)
	    {
		socket_perror ("write", imap->sock, n);
		return -1;
	    }
	    n = socket_write (imap->sock, "\r\n", 2);
	    if (n <= 0)
	    {
		socket_perror ("write", imap->sock, n);
		return -1;
	    }
	    imap->cram = 0;
	}
#endif
	else if ((size_t) atol (arg) != Tag)
	{
	    fprintf (stderr, "IMAP error: wrong tag\n");
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

static int
start_tls (imap_t *imap, config_t * cfg)
{
	int ret;

	/* initialize SSL */
	if (init_ssl (cfg))
		return 1;

	imap->sock->ssl = SSL_new (SSLContext);
	SSL_set_fd (imap->sock->ssl, imap->sock->fd);
	if ((ret = SSL_connect (imap->sock->ssl)) <= 0)
	{
		socket_perror ("connect", imap->sock, ret);
		return 1;
	}

	/* verify the server certificate */
	if (verify_cert (imap->sock->ssl))
		return 1;

	imap->sock->use_ssl = 1;
	puts ("SSL support enabled");
	return 0;
}

imap_t *
imap_connect (config_t * cfg)
{
  int s;
  struct sockaddr_in addr;
  struct hostent *he;
  imap_t *imap;
  char *arg, *rsp;
  int preauth;
#if HAVE_LIBSSL
  int use_ssl;
#endif
    int a[2];

    imap = calloc (1, sizeof (imap_t));
    imap->box = cfg;
    imap->sock = calloc (1, sizeof (Socket_t));
    imap->buf = calloc (1, sizeof (buffer_t));
    imap->buf->sock = imap->sock;
    imap->sock->fd = -1;

    /* open connection to IMAP server */

    if (cfg->tunnel)
    {
      info ("Starting tunnel '%s'...", cfg->tunnel);
      fflush (stdout);

      if (socketpair (PF_UNIX, SOCK_STREAM, 0, a))
      {
	perror ("socketpair");
	exit (1);
      }

      if (fork () == 0)
      {
	if (dup2 (a[0], 0) == -1 || dup2 (a[0], 1) == -1)
	{
	  _exit (127);
	}
	close (a[0]);
	close (a[1]);
	execl ("/bin/sh", "sh", "-c", cfg->tunnel, 0);
	_exit (127);
      }

      close (a[0]);

      imap->sock->fd = a[1];

      info ("ok\n");
    }
    else
    {
      memset (&addr, 0, sizeof (addr));
      addr.sin_port = htons (cfg->port);
      addr.sin_family = AF_INET;

      info ("Resolving %s... ", cfg->host);
      fflush (stdout);
      he = gethostbyname (cfg->host);
      if (!he)
      {
	perror ("gethostbyname");
	goto bail;
      }
      info ("ok\n");

      addr.sin_addr.s_addr = *((int *) he->h_addr_list[0]);

      s = socket (PF_INET, SOCK_STREAM, 0);

      info ("Connecting to %s:%hu... ", inet_ntoa (addr.sin_addr),
	     ntohs (addr.sin_port));
      fflush (stdout);
      if (connect (s, (struct sockaddr *) &addr, sizeof (addr)))
      {
	close (s);
	perror ("connect");
	goto bail;
      }
      info ("ok\n");

      imap->sock->fd = s;
    }

#if HAVE_LIBSSL
      use_ssl = 0;
      if (cfg->use_imaps) {
	if (start_tls (imap, cfg))
	  goto bail;
	use_ssl = 1;
      }
#endif

      /* read the greeting string */
      if (buffer_gets (imap->buf, &rsp))
      {
        fprintf (stderr, "IMAP error: no greeting response\n");
	goto bail;
      }
      arg = next_arg (&rsp);
      if (!arg || *arg != '*' || (arg = next_arg (&rsp)) == NULL)
      {
        fprintf (stderr, "IMAP error: invalid greeting response\n");
	goto bail;
      }
      preauth = 0;
      if (!strcmp ("PREAUTH", arg))
        preauth = 1;
      else if (strcmp ("OK", arg) != 0)
      {
        fprintf (stderr, "IMAP error: unknown greeting response\n");
	goto bail;
      }
      /* let's see what this puppy can do... */
      if (imap_exec (imap, "CAPABILITY"))
	goto bail;

#if HAVE_LIBSSL
      if (!cfg->use_imaps)
      {
	if (cfg->use_sslv2 || cfg->use_sslv3 || cfg->use_tlsv1)
	{
	  /* always try to select SSL support if available */
	  if (imap->have_starttls)
	  {
	    if (imap_exec (imap, "STARTTLS"))
	      goto bail;
	    if (start_tls (imap, cfg))
	      goto bail;
	    use_ssl = 1;

	    /* to conform to RFC2595 we need to forget all information
	     * retrieved from CAPABILITY invocations before STARTTLS.
	     */
	    imap->have_uidplus = 0;
	    imap->have_namespace = 0;
	    imap->have_cram = 0;
	    /* imap->have_starttls = 0; */
	    if (imap_exec (imap, "CAPABILITY"))
	      goto bail;
	  }
	  else
	  {
	    if (cfg->require_ssl)
	    {
	      fprintf (stderr, "IMAP error: SSL support not available\n");
	      goto bail;
	    }
	    else
	      fprintf (stderr, "IMAP warning: SSL support not available\n");
	  }
	}
      }
#endif

      if (!preauth)
      {
	info ("Logging in...\n");

	if (!cfg->pass)
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
	      perror ("getpass");
	      exit (1);
	    }
	    if (!*global.pass)
	    {
	      fprintf (stderr, "Skipping %s, no password\n", cfg->path);
	      global.pass = NULL; /* force retry */
	      goto bail;
	    }
	    /*
	     * getpass() returns a pointer to a static buffer.  make a copy
	     * for long term storage.
	     */
	    global.pass = strdup (global.pass);
	  }
	  cfg->pass = strdup (global.pass);
	}

#if HAVE_LIBSSL
	if (imap->have_cram)
	{
	  info ("Authenticating with CRAM-MD5\n");
	  imap->cram = 1;
	  if (imap_exec (imap, "AUTHENTICATE CRAM-MD5"))
	    goto bail;
	}
	else if (imap->box->require_cram)
	{
	  fprintf (stderr, "IMAP error: CRAM-MD5 authentication is not supported by server\n");
	  goto bail;
	}
	else
#endif
	{
#if HAVE_LIBSSL
	  if (!use_ssl)
#endif
	    fprintf (stderr, "*** IMAP Warning *** Password is being sent in the clear\n");
	  if (imap_exec (imap, "LOGIN \"%s\" \"%s\"", cfg->user, cfg->pass))
	  {
	    fprintf (stderr, "IMAP error: LOGIN failed\n");
	    goto bail;
	  }
	}
      }

      /* get NAMESPACE info */
      if (cfg->use_namespace && imap->have_namespace)
      {
	if (imap_exec (imap, "NAMESPACE"))
	  goto bail;
      }
      return imap;

 bail:
  imap_close (imap);
  return 0;
}

/* `box' is the config info for the maildrop to sync.  `minuid' is the
 * minimum UID to consider.  in normal mode this will be 1, but in --fast
 * mode we only fetch messages newer than the last one seen in the local
 * mailbox.
 */
imap_t *
imap_open (config_t * box, unsigned int minuid, imap_t * imap, int imap_create)
{
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
    }
    else
    {
      /* reset mailbox-specific state info */
      imap->box = box;
      imap->recent = 0;
      imap->deleted = 0;
      imap->count = 0;
      imap->maxuid = 0;
      free_message (imap->msgs);
      imap->msgs = 0;
      goto gotimap;
    }
  }
  if (!(imap = imap_connect (box)))
    return 0;
 gotimap:

  if (global.folder)
    imap->prefix = !strcmp (box->box, "INBOX") ? "" : global.folder;
  else
  {
    imap->prefix = "";
    /* XXX for now assume personal namespace */
    if (imap->box->use_namespace &&
	is_list (imap->ns_personal) &&
	is_list (imap->ns_personal->child) &&
	is_atom (imap->ns_personal->child->child))
      imap->prefix = imap->ns_personal->child->child->val;
  }

    info ("Selecting IMAP mailbox... ");
    fflush (stdout);
    if (imap_exec (imap, "SELECT \"%s%s\"", imap->prefix, box->box)) {
      if (imap_create) {
	if (imap_exec (imap, "CREATE \"%s%s\"", imap->prefix, box->box))
	  goto bail;
        if (imap_exec (imap, "SELECT \"%s%s\"", imap->prefix, box->box))
	  goto bail;
      } else
        goto bail;
    }
    info ("%d messages, %d recent\n", imap->count, imap->recent);

    info ("Reading IMAP mailbox index\n");
    imap->minuid = minuid;
    if (imap->count > 0)
    {
      if (imap_exec (imap, "UID FETCH %d:* (FLAGS RFC822.SIZE)", minuid))
	goto bail;
    }

    return imap;

 bail:
  imap_close (imap);
  return 0;
}

void
imap_close (imap_t * imap)
{
  if (imap)
  {
    if (imap->sock->fd != -1)
    {
      imap_exec (imap, "LOGOUT");
      close (imap->sock->fd);
    }
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
  if (Verbose) {
    printf (">>> %s", cmd);
    fflush (stdout);
  }
  n = socket_write (sock, cmd, strlen (cmd));
  if (n <= 0)
  {
    socket_perror ("write", sock, n);
    return -1;
  }

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
	info ("IMAP info: skipping untagged response: %s\n", arg);
	continue;
      }

      while ((arg = next_arg (&cmd)) && *arg != '{')
	;
      if (!arg)
      {
	fprintf (stderr, "IMAP error: parse error getting size\n");
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
    }
    else
    {
      arg = next_arg (&cmd);
      if (!arg || (size_t) atoi (arg) != Tag)
      {
	fprintf (stderr, "IMAP error: wrong tag\n");
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
  char *fmap;
  int extra, uid, tuidl = 0;
  char flagstr[128], tuid[128];
  char *s;
  size_t i;
  size_t start;
  size_t len, sbreak = 0, ebreak = 0;
  char *arg;
  struct timeval tv;
  pid_t pid = getpid();

  len = msg->size;
  /* ugh, we need to count the number of newlines */
  fmap = (char *)mmap (0, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (!fmap)
  {
    perror ("mmap");
    return -1;
  }

  extra = 0, i = 0;
  if (!imap->have_uidplus)
  {
   nloop:
    start = i;
    while (i < len)
      if (fmap[i++] == '\n')
      {
	extra++;
	if (i - 1 == start)
	{
	  sbreak = ebreak = i - 1;
	  goto mktid;
	}
	if (!memcmp (fmap + start, "X-TUID: ", 8))
	{
	  extra -= (ebreak = i) - (sbreak = start) + 1;
	  goto mktid;
	}
	goto nloop;
      }
    /* invalid mesasge */
    goto bail;
   mktid:
    gettimeofday (&tv, 0);
    tuidl = sprintf (tuid, "X-TUID: %08lx%05lx%04x\r\n", 
			   tv.tv_sec, tv.tv_usec, pid);
    extra += tuidl;
  }
  for (; i < len; i++)
    if (fmap[i] == '\n')
      extra++;

  flagstr[0] = 0;
  if (msg->flags)
  {
    if (msg->flags & D_DELETED)
      strcat (flagstr," \\Deleted");
    if (msg->flags & D_ANSWERED)
      strcat (flagstr," \\Answered");
    if (msg->flags & D_SEEN)
      strcat (flagstr," \\Seen");
    if (msg->flags & D_FLAGGED)
      strcat (flagstr," \\Flagged");
    if (msg->flags & D_DRAFT)
      strcat (flagstr," \\Draft");
    flagstr[0] = '(';
    strcat (flagstr,") ");
  }

  send_server (imap->sock, "APPEND %s%s %s{%d}",
	       imap->prefix, imap->box->box, flagstr, len + extra);

  if (buffer_gets (imap->buf, &s))
    goto bail;

  if (*s != '+')
  {
    fprintf (stderr, "IMAP error: expected `+' from server (aborting)\n");
    goto bail;
  }

  i = 0;
  if (!imap->have_uidplus)
  {
   n1loop:
    start = i;
    while (i < sbreak)
      if (fmap[i++] == '\n')
      {
	socket_write (imap->sock, fmap + start, i - 1 - start);
	socket_write (imap->sock, "\r\n", 2);
	goto n1loop;
      }
    socket_write (imap->sock, tuid, tuidl);
    i = ebreak;
  }
 n2loop:
  start = i;
  while (i < len)
    if (fmap[i++] == '\n')
    {
      socket_write (imap->sock, fmap + start, i - 1 - start);
      socket_write (imap->sock, "\r\n", 2);
      goto n2loop;
    }
  socket_write (imap->sock, fmap + start, len - start);
  socket_write (imap->sock, "\r\n", 2);

  munmap (fmap, len);

  for (;;)
  {
    if (buffer_gets (imap->buf, &s))
      return -1;

    arg = next_arg (&s);
    if (*arg == '*')
    {
      /* XXX just ignore it for now */
    }
    else if (atoi (arg) != (int) Tag)
    {
      fprintf (stderr, "IMAP error: wrong tag\n");
      return -1;
    }
    else
    {
      arg = next_arg (&s);
      if (strcmp (arg, "OK"))
	return -1;
      arg = next_arg (&s);
      if (*arg != '[')
	break;
      arg++;
      if (strcasecmp ("APPENDUID", arg))
      {
	fprintf (stderr, "IMAP error: expected APPENDUID\n");
	break;
      }
      arg = next_arg (&s);
      if (!arg)
	break;
      if (atoi (arg) != (int) imap->uidvalidity)
      {
	fprintf (stderr, "IMAP error: UIDVALIDITY doesn't match APPENDUID\n");
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

  /* didn't receive an APPENDUID */
  send_server (imap->sock,
	       "UID SEARCH HEADER X-TUID %08lx%05lx%04x", 
	       tv.tv_sec, tv.tv_usec, pid);
  uid = 0;
  for (;;)
  {
    if (buffer_gets (imap->buf, &s))
      return -1;

    arg = next_arg (&s);
    if (*arg == '*')
    {
      arg = next_arg (&s);
      if (!strcmp (arg, "SEARCH"))
      {
	arg = next_arg (&s);
	if (!arg)
	  fprintf (stderr, "IMAP error: incomplete SEARCH response\n");
	else
	  uid = atoi (arg);
      }
    }
    else if (atoi (arg) != (int) Tag)
    {
      fprintf (stderr, "IMAP error: wrong tag\n");
      return -1;
    }
    else
    {
      arg = next_arg (&s);
      if (strcmp (arg, "OK"))
	return -1;
      return uid;
    }
  }

  return 0;

 bail:
  munmap (fmap, len);
  return -1;
}

int
imap_list (imap_t * imap)
{
  return imap_exec (imap, "LIST \"\" \"%s*\"", global.folder);
}

