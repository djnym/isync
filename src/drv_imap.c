/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>
 * Copyright (C) 2004 Theodore Y. Ts'o <tytso@mit.edu>
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
 * As a special exception, mbsync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

#include "isync.h"

#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#if HAVE_LIBSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/hmac.h>
#endif

typedef struct imap_server_conf {
	struct imap_server_conf *next;
	char *name;
	char *tunnel;
	char *host;
	int port;
	char *user;
	char *pass;
#if HAVE_LIBSSL
	char *cert_file;
	unsigned use_imaps:1;
	unsigned require_ssl:1;
	unsigned use_sslv2:1;
	unsigned use_sslv3:1;
	unsigned use_tlsv1:1;
	unsigned require_cram:1;
#endif
} imap_server_conf_t;

typedef struct imap_store_conf {
	store_conf_t gen;
	imap_server_conf_t *server;
	unsigned use_namespace:1;
} imap_store_conf_t;

typedef struct imap_message {
	message_t gen;
/*	int seq; will be needed when expunges are tracked */
} imap_message_t;

#define NIL	(void*)0x1
#define LIST	(void*)0x2

typedef struct _list {
	struct _list *next, *child;
	char *val;
	int len;
} list_t;

typedef struct {
	int fd;
#if HAVE_LIBSSL
	SSL *ssl;
	unsigned int use_ssl:1;
#endif
} Socket_t;

typedef struct {
	Socket_t sock;
	int bytes;
	int offset;
	char buf[1024];
} buffer_t;

struct imap_cmd;
#define max_in_progress 50 /* make this configurable? */

typedef struct imap {
	int uidnext; /* from SELECT responses */
	list_t *ns_personal, *ns_other, *ns_shared; /* NAMESPACE info */
	string_list_t *boxes; /* LIST results */
	message_t **msgapp; /* FETCH results */
	unsigned caps, rcaps; /* CAPABILITY results */
	/* command queue */
	int nexttag, num_in_progress, literal_pending;
	struct imap_cmd *in_progress, **in_progress_append;
#if HAVE_LIBSSL
	SSL_CTX *SSLContext;
#endif
	buffer_t buf; /* this is BIG, so put it last */
} imap_t;

typedef struct imap_store {
	store_t gen;
	imap_t *imap;
	const char *prefix;
	unsigned /*currentnc:1,*/ trashnc:1;
} imap_store_t;

struct imap_cmd_cb {
	int (*cont)( imap_store_t *ctx, struct imap_cmd *cmd, const char *prompt );
	void (*done)( imap_store_t *ctx, struct imap_cmd *cmd, int response);
	void *ctx;
	char *data;
	int dlen;
	int uid;
	unsigned create:1, trycreate:1;
};

struct imap_cmd {
	struct imap_cmd *next;
	struct imap_cmd_cb cb;
	char *cmd;
	int tag;
};

#define CAP(cap) (imap->caps & (1 << (cap)))

enum CAPABILITY {
	NOLOGIN = 0,
	UIDPLUS,
	LITERALPLUS,
	NAMESPACE,
#if HAVE_LIBSSL
	CRAM,
	STARTTLS,
#endif
};

static const char *cap_list[] = {
	"LOGINDISABLED",
	"UIDPLUS",
	"LITERAL+",
	"NAMESPACE",
#if HAVE_LIBSSL
	"AUTH=CRAM-MD5",
	"STARTTLS",
#endif
};

#define RESP_OK    0
#define RESP_NO    1
#define RESP_BAD   2

static int get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd );


static const char *Flags[] = {
	"Draft",
	"Flagged",
	"Answered",
	"Seen",
	"Deleted",
};

#if HAVE_LIBSSL

/* this gets called when a certificate is to be verified */
static int
verify_cert( SSL *ssl )
{
	X509 *cert;
	int err;
	char buf[256];
	int ret = -1;
	BIO *bio;

	cert = SSL_get_peer_certificate( ssl );
	if (!cert) {
		fprintf( stderr, "Error, no server certificate\n" );
		return -1;
	}

	err = SSL_get_verify_result( ssl );
	if (err == X509_V_OK)
		return 0;

	fprintf( stderr, "Error, can't verify certificate: %s (%d)\n",
	         X509_verify_cert_error_string(err), err );

	X509_NAME_oneline( X509_get_subject_name( cert ), buf, sizeof(buf) );
	info( "\nSubject: %s\n", buf );
	X509_NAME_oneline( X509_get_issuer_name( cert ), buf, sizeof(buf) );
	info( "Issuer:  %s\n", buf );
	bio = BIO_new( BIO_s_mem() );
	ASN1_TIME_print( bio, X509_get_notBefore( cert ) );
	memset( buf, 0, sizeof(buf) );
	BIO_read( bio, buf, sizeof(buf) - 1 );
	info( "Valid from: %s\n", buf );
	ASN1_TIME_print( bio, X509_get_notAfter( cert ) );
	memset( buf, 0, sizeof(buf) );
	BIO_read( bio, buf, sizeof(buf) - 1 );
	BIO_free( bio );
	info( "      to:   %s\n", buf );

	fputs( "\n*** WARNING ***  There is no way to verify this certificate.  It is\n"
	       "                 possible that a hostile attacker has replaced the\n"
	       "                 server certificate.  Continue at your own risk!\n"
	       "\nAccept this certificate anyway? [no]: ",  stderr );
	if (fgets( buf, sizeof(buf), stdin ) && (buf[0] == 'y' || buf[0] == 'Y')) {
		ret = 0;
		fprintf( stderr, "\n*** Fine, but don't say I didn't warn you!\n\n" );
	}
	return ret;
}

static int
init_ssl_ctx( imap_store_t *ctx )
{
	imap_t *imap = ctx->imap;
	imap_store_conf_t *conf = (imap_store_conf_t *)ctx->gen.conf;
	imap_server_conf_t *srvc = conf->server;
	SSL_METHOD *method;
	int options = 0;

	if (srvc->use_tlsv1 && !srvc->use_sslv2 && !srvc->use_sslv3)
		method = TLSv1_client_method();
	else
		method = SSLv23_client_method();
	imap->SSLContext = SSL_CTX_new( method );

	if (!srvc->cert_file) {
		fprintf( stderr, "Error, CertificateFile not defined\n" );
		return -1;
	} else if (access( srvc->cert_file, R_OK ))
		warn( "*** Warning: can't read CertificateFile, so can't verify server certificates\n" );
	else if (!SSL_CTX_load_verify_locations( imap->SSLContext, srvc->cert_file, NULL )) {
		fprintf( stderr, "Error, SSL_CTX_load_verify_locations: %s\n",
		         ERR_error_string( ERR_get_error(), 0 ) );
		return -1;
	}

	if (!srvc->use_sslv2)
		options |= SSL_OP_NO_SSLv2;
	if (!srvc->use_sslv3)
		options |= SSL_OP_NO_SSLv3;
	if (!srvc->use_tlsv1)
		options |= SSL_OP_NO_TLSv1;

	SSL_CTX_set_options( imap->SSLContext, options );

	/* we check the result of the verification after SSL_connect() */
	SSL_CTX_set_verify( imap->SSLContext, SSL_VERIFY_NONE, 0 );
	return 0;
}
#endif /* HAVE_LIBSSL */

static void
socket_perror( const char *func, Socket_t *sock, int ret )
{
#if HAVE_LIBSSL
	int err;

	if (sock->use_ssl) {
		switch ((err = SSL_get_error( sock->ssl, ret ))) {
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
			if ((err = ERR_get_error()) == 0) {
				if (ret == 0)
					fprintf( stderr, "SSL_%s:got EOF\n", func );
				else
					fprintf( stderr, "SSL_%s:%d:%s\n", func, errno, strerror(errno) );
			} else
				fprintf( stderr, "SSL_%s:%d:%s\n", func, err, ERR_error_string( err, 0 ) );
			return;
		default:
			fprintf( stderr, "SSL_%s:%d:unhandled SSL error\n", func, err );
			break;
		}
		return;
	}
#else
	(void)sock;
#endif
	if (ret < 0)
		perror( func );
	else
		fprintf( stderr, "%s: unexpected EOF\n", func );
}

static int
socket_read( Socket_t *sock, char *buf, int len )
{
	int n =
#if HAVE_LIBSSL
		sock->use_ssl ? SSL_read( sock->ssl, buf, len ) :
#endif
		read( sock->fd, buf, len );
	if (n <= 0) {
		socket_perror( "read", sock, n );
		close( sock->fd );
		sock->fd = -1;
	}
	return n;
}

static int
socket_write( Socket_t *sock, char *buf, int len )
{
	int n =
#if HAVE_LIBSSL
		sock->use_ssl ? SSL_write( sock->ssl, buf, len ) :
#endif
		write( sock->fd, buf, len );
	if (n != len) {
		socket_perror( "write", sock, n );
		close( sock->fd );
		sock->fd = -1;
	}
	return n;
}

static int
socket_pending( Socket_t *sock )
{
	int num = -1;

	if (ioctl( sock->fd, FIONREAD, &num ) < 0)
		return -1;
	if (num > 0)
		return num;
#if HAVE_LIBSSL
	if (sock->use_ssl)
		return SSL_pending( sock->ssl );
#endif
	return 0;
}

/* simple line buffering */
static int
buffer_gets( buffer_t * b, char **s )
{
	int n;
	int start = b->offset;

	*s = b->buf + start;

	for (;;) {
		/* make sure we have enough data to read the \r\n sequence */
		if (b->offset + 1 >= b->bytes) {
			if (start) {
				/* shift down used bytes */
				*s = b->buf;

				assert( start <= b->bytes );
				n = b->bytes - start;

				if (n)
					memcpy( b->buf, b->buf + start, n );
				b->offset -= start;
				b->bytes = n;
				start = 0;
			}

			n = socket_read( &b->sock, b->buf + b->bytes,
			                 sizeof(b->buf) - b->bytes );

			if (n <= 0)
				return -1;

			b->bytes += n;
		}

		if (b->buf[b->offset] == '\r') {
			assert( b->offset + 1 < b->bytes );
			if (b->buf[b->offset + 1] == '\n') {
				b->buf[b->offset] = 0;  /* terminate the string */
				b->offset += 2; /* next line */
				if (Verbose)
					puts( *s );
				return 0;
			}
		}

		b->offset++;
	}
	/* not reached */
}

static struct imap_cmd *
v_issue_imap_cmd( imap_store_t *ctx, struct imap_cmd_cb *cb,
                  const char *fmt, va_list ap )
{
	imap_t *imap = ctx->imap;
	struct imap_cmd *cmd;
	int n, bufl;
	char buf[1024];

	cmd = nfmalloc( sizeof(struct imap_cmd) );
	nfvasprintf( &cmd->cmd, fmt, ap );
	cmd->tag = ++imap->nexttag;

	if (cb)
		cmd->cb = *cb;
	else
		memset( &cmd->cb, 0, sizeof(cmd->cb) );

	while (imap->literal_pending)
		get_cmd_result( ctx, 0 );

	bufl = nfsnprintf( buf, sizeof(buf), cmd->cb.data ? CAP(LITERALPLUS) ?
	                   "%d %s{%d+}\r\n" : "%d %s{%d}\r\n" : "%d %s\r\n",
	                   cmd->tag, cmd->cmd, cmd->cb.dlen );
	if (Verbose) {
		if (imap->num_in_progress)
			printf( "(%d in progress) ", imap->num_in_progress );
		if (memcmp( cmd->cmd, "LOGIN", 5 ))
			printf( ">>> %s", buf );
		else
			printf( ">>> %d LOGIN <user> <pass>\n", cmd->tag );
	}
	if (socket_write( &imap->buf.sock, buf, bufl ) != bufl) {
		free( cmd->cmd );
		free( cmd );
		if (cb && cb->data)
			free( cb->data );
		return NULL;
	}
	if (cmd->cb.data) {
		if (CAP(LITERALPLUS)) {
			n = socket_write( &imap->buf.sock, cmd->cb.data, cmd->cb.dlen );
			free( cmd->cb.data );
			if (n != cmd->cb.dlen ||
			    (n = socket_write( &imap->buf.sock, "\r\n", 2 )) != 2)
			{
				free( cmd->cmd );
				free( cmd );
				return NULL;
			}
			cmd->cb.data = 0;
		} else
			imap->literal_pending = 1;
	} else if (cmd->cb.cont)
		imap->literal_pending = 1;
	cmd->next = 0;
	*imap->in_progress_append = cmd;
	imap->in_progress_append = &cmd->next;
	imap->num_in_progress++;
	return cmd;
}

static struct imap_cmd *
issue_imap_cmd( imap_store_t *ctx, struct imap_cmd_cb *cb, const char *fmt, ... )
{
	struct imap_cmd *ret;
	va_list ap;

	va_start( ap, fmt );
	ret = v_issue_imap_cmd( ctx, cb, fmt, ap );
	va_end( ap );
	return ret;
}

static struct imap_cmd *
issue_imap_cmd_w( imap_store_t *ctx, struct imap_cmd_cb *cb, const char *fmt, ... )
{
	imap_t *imap = ctx->imap;
	struct imap_cmd *ret;
	va_list ap;

	va_start( ap, fmt );
	ret = v_issue_imap_cmd( ctx, cb, fmt, ap );
	va_end( ap );
	while (imap->num_in_progress > max_in_progress ||
	       socket_pending( &imap->buf.sock ))
		get_cmd_result( ctx, 0 );
	return ret;
}

static int
imap_exec( imap_store_t *ctx, struct imap_cmd_cb *cb, const char *fmt, ... )
{
	va_list ap;
	struct imap_cmd *cmdp;

	va_start( ap, fmt );
	cmdp = v_issue_imap_cmd( ctx, cb, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return RESP_BAD;

	return get_cmd_result( ctx, cmdp );
}

static int
imap_exec_b( imap_store_t *ctx, struct imap_cmd_cb *cb, const char *fmt, ... )
{
	va_list ap;
	struct imap_cmd *cmdp;

	va_start( ap, fmt );
	cmdp = v_issue_imap_cmd( ctx, cb, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return DRV_STORE_BAD;

	switch (get_cmd_result( ctx, cmdp )) {
	case RESP_BAD: return DRV_STORE_BAD;
	case RESP_NO: return DRV_BOX_BAD;
	default: return DRV_OK;
	}
}

static int
imap_exec_m( imap_store_t *ctx, struct imap_cmd_cb *cb, const char *fmt, ... )
{
	va_list ap;
	struct imap_cmd *cmdp;

	va_start( ap, fmt );
	cmdp = v_issue_imap_cmd( ctx, cb, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return DRV_STORE_BAD;

	switch (get_cmd_result( ctx, cmdp )) {
	case RESP_BAD: return DRV_STORE_BAD;
	case RESP_NO: return DRV_MSG_BAD;
	default: return DRV_OK;
	}
}

/*
static void
drain_imap_replies( imap_t *imap )
{
	while (imap->num_in_progress)
		get_cmd_result( imap, 0 );
}
*/

static int
is_atom( list_t *list )
{
	return list && list->val && list->val != NIL && list->val != LIST;
}

static int
is_list( list_t *list )
{
	return list && list->val == LIST;
}

static void
free_list( list_t *list )
{
	list_t *tmp;

	for (; list; list = tmp) {
		tmp = list->next;
		if (is_list( list ))
			free_list( list->child );
		else if (is_atom( list ))
			free( list->val );
		free( list );
	}
}

static int
parse_imap_list_l( imap_t *imap, char **sp, list_t **curp, int level )
{
	list_t *cur;
	char *s = *sp, *p;
	int n, bytes;

	for (;;) {
		while (isspace( (unsigned char)*s ))
			s++;
		if (level && *s == ')') {
			s++;
			break;
		}
		*curp = cur = nfmalloc( sizeof(*cur) );
		curp = &cur->next;
		cur->val = 0; /* for clean bail */
		if (*s == '(') {
			/* sublist */
			s++;
			cur->val = LIST;
			if (parse_imap_list_l( imap, &s, &cur->child, level + 1 ))
				goto bail;
		} else if (imap && *s == '{') {
			/* literal */
			bytes = cur->len = strtol( s + 1, &s, 10 );
			if (*s != '}')
				goto bail;

			s = cur->val = nfmalloc( cur->len );

			/* dump whats left over in the input buffer */
			n = imap->buf.bytes - imap->buf.offset;

			if (n > bytes)
				/* the entire message fit in the buffer */
				n = bytes;

			memcpy( s, imap->buf.buf + imap->buf.offset, n );
			s += n;
			bytes -= n;

			/* mark that we used part of the buffer */
			imap->buf.offset += n;

			/* now read the rest of the message */
			while (bytes > 0) {
				if ((n = socket_read (&imap->buf.sock, s, bytes)) <= 0)
					goto bail;
				s += n;
				bytes -= n;
			}

			if (buffer_gets( &imap->buf, &s ))
				goto bail;
		} else if (*s == '"') {
			/* quoted string */
			s++;
			p = s;
			for (; *s != '"'; s++)
				if (!*s)
					goto bail;
			cur->len = s - p;
			s++;
			cur->val = nfmalloc( cur->len + 1 );
			memcpy( cur->val, p, cur->len );
			cur->val[cur->len] = 0;
		} else {
			/* atom */
			p = s;
			for (; *s && !isspace( (unsigned char)*s ); s++)
				if (level && *s == ')')
					break;
			cur->len = s - p;
			if (cur->len == 3 && !memcmp ("NIL", p, 3))
				cur->val = NIL;
			else {
				cur->val = nfmalloc( cur->len + 1 );
				memcpy( cur->val, p, cur->len );
				cur->val[cur->len] = 0;
			}
		}

		if (!level)
			break;
		if (!*s)
			goto bail;
	}
	*sp = s;
	*curp = 0;
	return 0;

  bail:
	*curp = 0;
	return -1;
}

static list_t *
parse_imap_list( imap_t *imap, char **sp )
{
	list_t *head;

	if (!parse_imap_list_l( imap, sp, &head, 0 ))
		return head;
	free_list( head );
	return NULL;
}

static list_t *
parse_list( char **sp )
{
	return parse_imap_list( 0, sp );
}

static int
parse_fetch( imap_t *imap, char *cmd ) /* move this down */
{
	list_t *tmp, *list, *flags;
	char *body = 0;
	imap_message_t *cur;
	msg_data_t *msgdata;
	struct imap_cmd *cmdp;
	int uid = 0, mask = 0, status = 0, size = 0;
	unsigned i;

	list = parse_imap_list( imap, &cmd );

	if (!is_list( list )) {
		fprintf( stderr, "IMAP error: bogus FETCH response\n" );
		free_list( list );
		return -1;
	}

	for (tmp = list->child; tmp; tmp = tmp->next) {
		if (is_atom( tmp )) {
			if (!strcmp( "UID", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp ))
					uid = atoi( tmp->val );
				else
					fprintf( stderr, "IMAP error: unable to parse UID\n" );
			} else if (!strcmp( "FLAGS", tmp->val )) {
				tmp = tmp->next;
				if (is_list( tmp )) {
					for (flags = tmp->child; flags; flags = flags->next) {
						if (is_atom( flags )) {
							if (flags->val[0] == '\\') { /* ignore user-defined flags for now */
								if (!strcmp( "Recent", flags->val + 1)) {
									status |= M_RECENT;
									goto flagok;
								}
								for (i = 0; i < as(Flags); i++)
									if (!strcmp( Flags[i], flags->val + 1 )) {
										mask |= 1 << i;
										goto flagok;
									}
								fprintf( stderr, "IMAP warning: unknown system flag %s\n", flags->val );
							}
						  flagok: ;
						} else
							fprintf( stderr, "IMAP error: unable to parse FLAGS list\n" );
					}
					status |= M_FLAGS;
				} else
					fprintf( stderr, "IMAP error: unable to parse FLAGS\n" );
			} else if (!strcmp( "RFC822.SIZE", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp ))
					size = atoi( tmp->val );
				else
					fprintf( stderr, "IMAP error: unable to parse SIZE\n" );
			} else if (!strcmp( "BODY[]", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp )) {
					body = tmp->val;
					tmp->val = 0;       /* don't free together with list */
					size = tmp->len;
				} else
					fprintf( stderr, "IMAP error: unable to parse BODY[]\n" );
			}
		}
	}

	if (body) {
		for (cmdp = imap->in_progress; cmdp; cmdp = cmdp->next)
			if (cmdp->cb.uid == uid)
				goto gotuid;
		fprintf( stderr, "IMAP error: unexpected FETCH response (UID %d)\n", uid );
		free_list( list );
		return -1;
	  gotuid:
		msgdata = (msg_data_t *)cmdp->cb.ctx;
		msgdata->data = body;
		msgdata->len = size;
		msgdata->crlf = 1;
		if (status & M_FLAGS)
			msgdata->flags = mask;
	} else if (uid) { /* ignore async flag updates for now */
		/* XXX this will need sorting for out-of-order (multiple queries) */
		cur = nfcalloc( sizeof(*cur) );
		*imap->msgapp = &cur->gen;
		imap->msgapp = &cur->gen.next;
		cur->gen.next = 0;
		cur->gen.uid = uid;
		cur->gen.flags = mask;
		cur->gen.status = status;
		cur->gen.size = size;
	}

	free_list( list );
	return 0;
}

static void
parse_capability( imap_t *imap, char *cmd )
{
	char *arg;
	unsigned i;

	imap->caps = 0x80000000;
	while ((arg = next_arg( &cmd )))
		for (i = 0; i < as(cap_list); i++)
			if (!strcmp( cap_list[i], arg ))
				imap->caps |= 1 << i;
	imap->rcaps = imap->caps;
}

static int
parse_response_code( imap_store_t *ctx, struct imap_cmd_cb *cb, char *s )
{
	imap_t *imap = ctx->imap;
	char *arg, *p;

	if (*s != '[')
		return RESP_OK;		/* no response code */
	s++;
	if (!(p = strchr( s, ']' ))) {
		fprintf( stderr, "IMAP error: malformed response code\n" );
		return RESP_BAD;
	}
	*p++ = 0;
	arg = next_arg( &s );
	if (!strcmp( "UIDVALIDITY", arg )) {
		if (!(arg = next_arg( &s )) || !(ctx->gen.uidvalidity = atoi( arg ))) {
			fprintf( stderr, "IMAP error: malformed UIDVALIDITY status\n" );
			return RESP_BAD;
		}
	} else if (!strcmp( "UIDNEXT", arg )) {
		if (!(arg = next_arg( &s )) || !(imap->uidnext = atoi( arg ))) {
			fprintf( stderr, "IMAP error: malformed NEXTUID status\n" );
			return RESP_BAD;
		}
	} else if (!strcmp( "CAPABILITY", arg )) {
		parse_capability( imap, s );
	} else if (!strcmp( "ALERT", arg )) {
		/* RFC2060 says that these messages MUST be displayed
		 * to the user
		 */
		for (; isspace( (unsigned char)*p ); p++);
		fprintf( stderr, "*** IMAP ALERT *** %s\n", p );
	} else if (cb && cb->ctx && !strcmp( "APPENDUID", arg )) {
		if (!(arg = next_arg( &s )) || !(ctx->gen.uidvalidity = atoi( arg )) ||
		    !(arg = next_arg( &s )) || !(*(int *)cb->ctx = atoi( arg )))
		{
			fprintf( stderr, "IMAP error: malformed APPENDUID status\n" );
			return RESP_BAD;
		}
	}
	return RESP_OK;
}

static void
parse_search( imap_t *imap, char *cmd )
{
	char *arg;
	struct imap_cmd *cmdp;
	int uid;

	arg = next_arg( &cmd );
	if (!arg || !(uid = atoi( arg ))) {
		fprintf( stderr, "IMAP error: malformed SEARCH response\n" );
		return;
	}

	/* Find the first command that expects a UID - this is guaranteed
	 * to come in-order, as there are no other means to identify which
	 * SEARCH response belongs to which request.
	 */
	for (cmdp = imap->in_progress; cmdp; cmdp = cmdp->next)
		if (cmdp->cb.uid == -1) {
			*(int *)cmdp->cb.ctx = uid;
			return;
		}
	fprintf( stderr, "IMAP error: unexpected SEARCH response (UID %u)\n", uid );
}

static void
parse_list_rsp( imap_store_t *ctx, char *cmd )
{
	imap_t *imap = ctx->imap;
	char *arg;
	list_t *list, *lp;
	int l;

	list = parse_list( &cmd );
	if (list->val == LIST)
		for (lp = list->child; lp; lp = lp->next)
			if (is_atom( lp ) && !strcasecmp( lp->val, "\\NoSelect" )) {
				free_list( list );
				return;
			}
	free_list( list );
	(void) next_arg( &cmd ); /* skip delimiter */
	arg = next_arg( &cmd );
	l = strlen( ctx->gen.conf->path );
	if (memcmp( arg, ctx->gen.conf->path, l ))
		return;
	arg += l;
	if (!memcmp( arg + strlen( arg ) - 5, ".lock", 5 )) /* workaround broken servers */
		return;
	add_string_list( &imap->boxes, arg );
}

static int
get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd )
{
	imap_t *imap = ctx->imap;
	struct imap_cmd *cmdp, **pcmdp, *ncmdp;
	char *cmd, *arg, *arg1, *p;
	int n, resp, resp2, tag;

	for (;;) {
		if (buffer_gets( &imap->buf, &cmd ))
			return RESP_BAD;

		arg = next_arg( &cmd );
		if (*arg == '*') {
			arg = next_arg( &cmd );
			if (!arg) {
				fprintf( stderr, "IMAP error: unable to parse untagged response\n" );
				return RESP_BAD;
			}

			if (!strcmp( "NAMESPACE", arg )) {
				imap->ns_personal = parse_list( &cmd );
				imap->ns_other = parse_list( &cmd );
				imap->ns_shared = parse_list( &cmd );
			} else if (!strcmp( "OK", arg ) || !strcmp( "BAD", arg ) ||
			           !strcmp( "NO", arg ) || !strcmp( "BYE", arg )) {
				if ((resp = parse_response_code( ctx, 0, cmd )) != RESP_OK)
					return resp;
			} else if (!strcmp( "CAPABILITY", arg ))
				parse_capability( imap, cmd );
			else if (!strcmp( "LIST", arg ))
				parse_list_rsp( ctx, cmd );
			else if (!strcmp( "SEARCH", arg ))
				parse_search( imap, cmd );
			else if ((arg1 = next_arg( &cmd ))) {
				if (!strcmp( "EXISTS", arg1 ))
					ctx->gen.count = atoi( arg );
				else if (!strcmp( "RECENT", arg1 ))
					ctx->gen.recent = atoi( arg );
				else if(!strcmp ( "FETCH", arg1 )) {
					if (parse_fetch( imap, cmd ))
						return RESP_BAD;
				}
			} else {
				fprintf( stderr, "IMAP error: unable to parse untagged response\n" );
				return RESP_BAD;
			}
		} else if (!imap->in_progress) {
			fprintf( stderr, "IMAP error: unexpected reply: %s %s\n", arg, cmd ? cmd : "" );
			return RESP_BAD;
		} else if (*arg == '+') {
			/* This can happen only with the last command underway, as
			   it enforces a round-trip. */
			cmdp = (struct imap_cmd *)((char *)imap->in_progress_append -
			       offsetof(struct imap_cmd, next));
			if (cmdp->cb.data) {
				n = socket_write( &imap->buf.sock, cmdp->cb.data, cmdp->cb.dlen );
				free( cmdp->cb.data );
				cmdp->cb.data = 0;
				if (n != (int)cmdp->cb.dlen)
					return RESP_BAD;
			} else if (cmdp->cb.cont) {
				if (cmdp->cb.cont( ctx, cmdp, cmd ))
					return RESP_BAD;
			} else {
				fprintf( stderr, "IMAP error: unexpected command continuation request\n" );
				return RESP_BAD;
			}
			if (socket_write( &imap->buf.sock, "\r\n", 2 ) != 2)
				return RESP_BAD;
			if (!cmdp->cb.cont)
				imap->literal_pending = 0;
			if (!tcmd)
				return DRV_OK;
		} else {
			tag = atoi( arg );
			for (pcmdp = &imap->in_progress; (cmdp = *pcmdp); pcmdp = &cmdp->next)
				if (cmdp->tag == tag)
					goto gottag;
			fprintf( stderr, "IMAP error: unexpected tag %s\n", arg );
			return RESP_BAD;
		  gottag:
			if (!(*pcmdp = cmdp->next))
				imap->in_progress_append = pcmdp;
			imap->num_in_progress--;
			if (cmdp->cb.cont || cmdp->cb.data)
				imap->literal_pending = 0;
			arg = next_arg( &cmd );
			if (!strcmp( "OK", arg ))
				resp = DRV_OK;
			else {
				if (!strcmp( "NO", arg )) {
					if (cmdp->cb.create && cmd && (cmdp->cb.trycreate || !memcmp( cmd, "[TRYCREATE]", 11 ))) { /* SELECT, APPEND or UID COPY */
						p = strchr( cmdp->cmd, '"' );
						if (!issue_imap_cmd( ctx, 0, "CREATE \"%.*s\"", strchr( p + 1, '"' ) - p + 1, p )) {
							resp = RESP_BAD;
							goto normal;
						}
						/* not waiting here violates the spec, but a server that does not
						   grok this nonetheless violates it too. */
						cmdp->cb.create = 0;
						if (!(ncmdp = issue_imap_cmd( ctx, &cmdp->cb, "%s", cmdp->cmd ))) {
							resp = RESP_BAD;
							goto normal;
						}
						free( cmdp->cmd );
						free( cmdp );
						if (!tcmd)
							return 0;	/* ignored */
						if (cmdp == tcmd)
							tcmd = ncmdp;
						continue;
					}
					resp = RESP_NO;
				} else /*if (!strcmp( "BAD", arg ))*/
					resp = RESP_BAD;
				fprintf( stderr, "IMAP command '%s' returned an error: %s %s\n",
				         memcmp (cmdp->cmd, "LOGIN", 5) ?
				         		cmdp->cmd : "LOGIN <user> <pass>",
				         		arg, cmd ? cmd : "");
			}
			if ((resp2 = parse_response_code( ctx, &cmdp->cb, cmd )) > resp)
				resp = resp2;
		  normal:
			if (cmdp->cb.done)
				cmdp->cb.done( ctx, cmdp, resp );
			if (cmdp->cb.data)
				free( cmdp->cb.data );
			free( cmdp->cmd );
			free( cmdp );
			if (!tcmd || tcmd == cmdp)
				return resp;
		}
	}
	/* not reached */
}

static void
imap_close_server( imap_store_t *ictx )
{
	imap_t *imap = ictx->imap;

	if (imap->buf.sock.fd != -1) {
		imap_exec( ictx, 0, "LOGOUT" );
		close( imap->buf.sock.fd );
	}
#ifdef HAVE_LIBSSL
	if (imap->SSLContext)
		SSL_CTX_free( imap->SSLContext );
#endif
	free_list( imap->ns_personal );
	free_list( imap->ns_other );
	free_list( imap->ns_shared );
	free( imap );
}

static void
imap_close_store( store_t *ctx )
{
	imap_close_server( (imap_store_t *)ctx );
	free_generic_messages( ctx->msgs );
	free( ctx );
}

#ifdef HAVE_LIBSSL
static int
start_tls( imap_store_t *ctx )
{
	imap_t *imap = ctx->imap;
	int ret;
	static int ssl_inited;

	if (!ssl_inited) {
		SSL_library_init();
		SSL_load_error_strings();
		ssl_inited = 1;
	}

        if (init_ssl_ctx( ctx ))
		return 1;

	imap->buf.sock.ssl = SSL_new( imap->SSLContext );
	SSL_set_fd( imap->buf.sock.ssl, imap->buf.sock.fd );
	if ((ret = SSL_connect( imap->buf.sock.ssl )) <= 0) {
		socket_perror( "connect", &imap->buf.sock, ret );
		return 1;
	}

	/* verify the server certificate */
	if (verify_cert( imap->buf.sock.ssl ))
		return 1;

	imap->buf.sock.use_ssl = 1;
	info( "Connection is now encrypted\n" );
	return 0;
}

#define ENCODED_SIZE(n) (4*((n+2)/3))

static char
hexchar( unsigned int b )
{
	if (b < 10)
		return '0' + b;
	return 'a' + (b - 10);
}

/* XXX merge into do_cram_auth? */
static char *
cram( const char *challenge, const char *user, const char *pass )
{
	HMAC_CTX hmac;
	char hash[16];
	char hex[33];
	int i;
	unsigned int hashlen = sizeof(hash);
	char buf[256];
	int len = strlen( challenge );
	char *response = nfcalloc( 1 + len );
	char *final;

	/* response will always be smaller than challenge because we are
	 * decoding.
	 */
	len = EVP_DecodeBlock( (unsigned char *)response, (unsigned char *)challenge, strlen( challenge ) );

	HMAC_Init( &hmac, (unsigned char *) pass, strlen( pass ), EVP_md5() );
	HMAC_Update( &hmac, (unsigned char *)response, strlen( response ) );
	HMAC_Final( &hmac, (unsigned char *)hash, &hashlen );

	assert( hashlen == sizeof(hash) );

	free( response );

	hex[32] = 0;
	for (i = 0; i < 16; i++) {
		hex[2 * i] = hexchar( (hash[i] >> 4) & 0xf );
		hex[2 * i + 1] = hexchar( hash[i] & 0xf );
	}

	nfsnprintf( buf, sizeof(buf), "%s %s", user, hex );

	len = strlen( buf );
	len = ENCODED_SIZE( len ) + 1;
	final = nfmalloc( len );
	final[len - 1] = 0;

	assert( EVP_EncodeBlock( (unsigned char *)final, (unsigned char *)buf, strlen( buf ) ) == len - 1 );

	return final;
}

static int
do_cram_auth (imap_store_t *ctx, struct imap_cmd *cmdp, const char *prompt)
{
	imap_t *imap = ctx->imap;
	imap_server_conf_t *srvc = ((imap_store_conf_t *)ctx->gen.conf)->server;
	char *resp;
	int n, l;

	resp = cram( prompt, srvc->user, srvc->pass );

	if (Verbose)
		printf( ">+> %s\n", resp );
	l = strlen( resp );
	n = socket_write( &imap->buf.sock, resp, l );
	free( resp );
	if (n != l)
		return -1;
	cmdp->cb.cont = 0;
	return 0;
}
#endif

static store_t *
imap_open_store( store_conf_t *conf, store_t *oldctx )
{
	imap_store_conf_t *cfg = (imap_store_conf_t *)conf;
	imap_server_conf_t *srvc = cfg->server;
	imap_store_t *ctx = (imap_store_t *)oldctx;
	imap_t *imap;
	char *arg, *rsp;
	struct hostent *he;
	struct sockaddr_in addr;
	int s, a[2], preauth;
#if HAVE_LIBSSL
	int use_ssl;
#endif

	if (ctx) {
		if (((imap_store_conf_t *)(ctx->gen.conf))->server == cfg->server) {
			 ctx->gen.conf = conf;
			 imap = ctx->imap;
			 goto final;
		}
		imap_close_server( ctx );
	} else
		ctx = nfcalloc( sizeof(*ctx) );

	ctx->gen.conf = conf;
	ctx->imap = imap = nfcalloc( sizeof(*imap) );
	imap->buf.sock.fd = -1;
	imap->in_progress_append = &imap->in_progress;

	/* open connection to IMAP server */
#if HAVE_LIBSSL
	use_ssl = 0;
#endif

	if (srvc->tunnel) {
		info( "Starting tunnel '%s'... ", srvc->tunnel );

		if (socketpair( PF_UNIX, SOCK_STREAM, 0, a )) {
			perror( "socketpair" );
			exit( 1 );
		}

		if (fork() == 0) {
			if (dup2( a[0], 0 ) == -1 || dup2( a[0], 1 ) == -1)
				_exit( 127 );
			close( a[0] );
			close( a[1] );
			execl( "/bin/sh", "sh", "-c", srvc->tunnel, (char *)0 );
			_exit( 127 );
		}

		close (a[0]);

		imap->buf.sock.fd = a[1];

		info( "ok\n" );
	} else {
		memset( &addr, 0, sizeof(addr) );
		addr.sin_port = htons( srvc->port );
		addr.sin_family = AF_INET;

		info( "Resolving %s... ", srvc->host );
		he = gethostbyname( srvc->host );
		if (!he) {
			perror( "gethostbyname" );
			goto bail;
		}
		info( "ok\n" );

		addr.sin_addr.s_addr = *((int *) he->h_addr_list[0]);

		s = socket( PF_INET, SOCK_STREAM, 0 );

		info( "Connecting to %s:%hu... ", inet_ntoa( addr.sin_addr ), ntohs( addr.sin_port ) );
		if (connect( s, (struct sockaddr *)&addr, sizeof(addr) )) {
			close( s );
			perror( "connect" );
			goto bail;
		}
		info( "ok\n" );

		imap->buf.sock.fd = s;

#if HAVE_LIBSSL
		if (srvc->use_imaps) {
			if (start_tls( ctx ))
				goto bail;
			use_ssl = 1;
		}
#endif
	}

	/* read the greeting string */
	if (buffer_gets( &imap->buf, &rsp )) {
		fprintf( stderr, "IMAP error: no greeting response\n" );
		goto bail;
	}
	arg = next_arg( &rsp );
	if (!arg || *arg != '*' || (arg = next_arg( &rsp )) == NULL) {
		fprintf( stderr, "IMAP error: invalid greeting response\n" );
		goto bail;
	}
	preauth = 0;
	if (!strcmp( "PREAUTH", arg ))
		preauth = 1;
	else if (strcmp( "OK", arg ) != 0) {
		fprintf( stderr, "IMAP error: unknown greeting response\n" );
		goto bail;
	}
	parse_response_code( ctx, 0, rsp );
	if (!imap->caps && imap_exec( ctx, 0, "CAPABILITY" ) != RESP_OK)
		goto bail;

	if (!preauth) {
#if HAVE_LIBSSL
		if (!srvc->use_imaps && (srvc->use_sslv2 || srvc->use_sslv3 || srvc->use_tlsv1)) {
			/* always try to select SSL support if available */
			if (CAP(STARTTLS)) {
				if (imap_exec( ctx, 0, "STARTTLS" ) != RESP_OK)
					goto bail;
				if (start_tls( ctx ))
					goto bail;
				use_ssl = 1;

				if (imap_exec( ctx, 0, "CAPABILITY" ) != RESP_OK)
					goto bail;
			} else {
				if (srvc->require_ssl) {
					fprintf( stderr, "IMAP error: SSL support not available\n" );
					goto bail;
				} else
					warn( "IMAP warning: SSL support not available\n" );
			}
		}
#endif

		info ("Logging in...\n");
		if (!srvc->user) {
			fprintf( stderr, "Skipping server %s, no user\n", srvc->host );
			goto bail;
		}
		if (!srvc->pass) {
			char prompt[80];
			sprintf( prompt, "Password (%s@%s): ", srvc->user, srvc->host );
			arg = getpass( prompt );
			if (!arg) {
				perror( "getpass" );
				exit( 1 );
			}
			if (!*arg) {
				fprintf( stderr, "Skipping account %s@%s, no password\n", srvc->user, srvc->host );
				goto bail;
			}
			/*
			 * getpass() returns a pointer to a static buffer.  make a copy
			 * for long term storage.
			 */
			srvc->pass = nfstrdup( arg );
		}
#if HAVE_LIBSSL
		if (CAP(CRAM)) {
			struct imap_cmd_cb cb;

			info( "Authenticating with CRAM-MD5\n" );
			memset( &cb, 0, sizeof(cb) );
			cb.cont = do_cram_auth;
			if (imap_exec( ctx, &cb, "AUTHENTICATE CRAM-MD5" ) != RESP_OK)
				goto bail;
		} else if (srvc->require_cram) {
			fprintf( stderr, "IMAP error: CRAM-MD5 authentication is not supported by server\n" );
			goto bail;
		} else
#endif
		{
			if (CAP(NOLOGIN)) {
				fprintf( stderr, "Skipping account %s@%s, server forbids LOGIN\n", srvc->user, srvc->host );
				goto bail;
			}
#if HAVE_LIBSSL
			if (!use_ssl)
#endif
				warn( "*** IMAP Warning *** Password is being sent in the clear\n" );
			if (imap_exec( ctx, 0, "LOGIN \"%s\" \"%s\"", srvc->user, srvc->pass ) != RESP_OK) {
				fprintf( stderr, "IMAP error: LOGIN failed\n" );
				goto bail;
			}
		}
	} /* !preauth */

  final:
	ctx->prefix = "";
	if (*conf->path)
		ctx->prefix = conf->path;
	else if (cfg->use_namespace && CAP(NAMESPACE)) {
		/* get NAMESPACE info */
		if (imap_exec( ctx, 0, "NAMESPACE" ) != RESP_OK)
			goto bail;
		/* XXX for now assume personal namespace */
		if (is_list( imap->ns_personal ) &&
		    is_list( imap->ns_personal->child ) &&
		    is_atom( imap->ns_personal->child->child ))
			ctx->prefix = imap->ns_personal->child->child->val;
	}
	ctx->trashnc = 1;
	return (store_t *)ctx;

  bail:
	imap_close_store( &ctx->gen );
	return 0;
}

static void
imap_prepare( store_t *gctx, int opts )
{
	free_generic_messages( gctx->msgs );
	gctx->msgs = 0;
	gctx->opts = opts;
}

static int
imap_select( store_t *gctx, int minuid, int maxuid, int *excs, int nexcs )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	imap_t *imap = ctx->imap;
	const char *prefix;
	int ret, i, j, bl;
	struct imap_cmd_cb cb;
	char buf[1000];


	if (!strcmp( gctx->name, "INBOX" )) {
//		imap->currentnc = 0;
		prefix = "";
	} else {
//		imap->currentnc = 1;	/* could use LIST results for that */
		prefix = ctx->prefix;
	}

	memset( &cb, 0, sizeof(cb) );
	cb.create = (gctx->opts & OPEN_CREATE) != 0;
	cb.trycreate = 1;
	if ((ret = imap_exec_b( ctx, &cb, "SELECT \"%s%s\"", prefix, gctx->name )) != DRV_OK)
		goto bail;

	if (gctx->count) {
		imap->msgapp = &gctx->msgs;
		sort_ints( excs, nexcs );
		for (i = 0; i < nexcs; ) {
			for (bl = 0; i < nexcs && bl < 960; i++) {
				if (bl)
					buf[bl++] = ',';
				bl += sprintf( buf + bl, "%d", excs[i] );
				j = i;
				for (; i + 1 < nexcs && excs[i + 1] == excs[i] + 1; i++);
				if (i != j)
					bl += sprintf( buf + bl, ":%d", excs[i] );
			}
			if ((ret = imap_exec_b( ctx, 0, "UID FETCH %s (UID%s%s)", buf,
			                        (gctx->opts & OPEN_FLAGS) ? " FLAGS" : "",
			                        (gctx->opts & OPEN_SIZE) ? " RFC822.SIZE" : "" )) != DRV_OK)
				goto bail;
		}
		if (maxuid == INT_MAX)
			maxuid = imap->uidnext ? imap->uidnext - 1 : 1000000000;
		if (maxuid >= minuid &&
		    (ret = imap_exec_b( ctx, 0, "UID FETCH %d:%d (UID%s%s)", minuid, maxuid,
		                        (gctx->opts & OPEN_FLAGS) ? " FLAGS" : "",
		                        (gctx->opts & OPEN_SIZE) ? " RFC822.SIZE" : "" )) != DRV_OK)
			goto bail;
	}

	ret = DRV_OK;

  bail:
	if (excs)
		free( excs );
	return ret;
}

static int
imap_fetch_msg( store_t *ctx, message_t *msg, msg_data_t *data )
{
	struct imap_cmd_cb cb;

	memset( &cb, 0, sizeof(cb) );
	cb.uid = msg->uid;
	cb.ctx = data;
	return imap_exec_m( (imap_store_t *)ctx, &cb, "UID FETCH %d (%sBODY.PEEK[])",
	                    msg->uid, (msg->status & M_FLAGS) ? "" : "FLAGS " );
}

static int
imap_make_flags( int flags, char *buf )
{
	const char *s;
	unsigned i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i)) {
			buf[d++] = ' ';
			buf[d++] = '\\';
			for (s = Flags[i]; *s; s++)
				buf[d++] = *s;
		}
	buf[0] = '(';
	buf[d++] = ')';
	return d;
}

static int
imap_flags_helper( imap_store_t *ctx, int uid, char what, int flags)
{
	char buf[256];

	buf[imap_make_flags( flags, buf )] = 0;
	return issue_imap_cmd_w( ctx, 0, "UID STORE %d %cFLAGS.SILENT %s", uid, what, buf ) ? DRV_OK : DRV_STORE_BAD;
}

static int
imap_set_flags( store_t *gctx, message_t *msg, int uid, int add, int del )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	int ret;

	if (msg) {
		uid = msg->uid;
		add &= ~msg->flags;
		del &= msg->flags;
		msg->flags |= add;
		msg->flags &= ~del;
	}
	if ((!add || (ret = imap_flags_helper( ctx, uid, '+', add )) == DRV_OK) &&
	    (!del || (ret = imap_flags_helper( ctx, uid, '-', del )) == DRV_OK))
		return DRV_OK;
	return ret;
}

static int
imap_close( store_t *ctx )
{
	return imap_exec_b( (imap_store_t *)ctx, 0, "CLOSE" );
}

static int
imap_trash_msg( store_t *gctx, message_t *msg )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_cb cb;

	memset( &cb, 0, sizeof(cb) );
	cb.create = 1;
	return imap_exec_m( ctx, &cb, "UID COPY %d \"%s%s\"",
	                    msg->uid, ctx->prefix, gctx->conf->trash );
}

#define TUIDL 8

static int
imap_store_msg( store_t *gctx, msg_data_t *data, int *uid )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	imap_t *imap = ctx->imap;
	struct imap_cmd_cb cb;
	char *fmap, *buf;
	const char *prefix, *box;
	int ret, i, j, d, len, extra, nocr;
	int start, sbreak = 0, ebreak = 0;
	char flagstr[128], tuid[TUIDL * 2 + 1];

	memset( &cb, 0, sizeof(cb) );

	fmap = data->data;
	len = data->len;
	nocr = !data->crlf;
	extra = 0, i = 0;
	if (!CAP(UIDPLUS) && uid) {
	  nloop:
		start = i;
		while (i < len)
			if (fmap[i++] == '\n') {
				extra += nocr;
				if (i - 2 + nocr == start) {
					sbreak = ebreak = i - 2 + nocr;
					goto mktid;
				}
				if (!memcmp( fmap + start, "X-TUID: ", 8 )) {
					extra -= (ebreak = i) - (sbreak = start) + nocr;
					goto mktid;
				}
				goto nloop;
			}
		/* invalid message */
		free( fmap );
		return DRV_MSG_BAD;
	 mktid:
		for (j = 0; j < TUIDL; j++)
			sprintf( tuid + j * 2, "%02x", arc4_getbyte() );
		extra += 8 + TUIDL * 2 + 2;
	}
	if (nocr)
		for (; i < len; i++)
			if (fmap[i] == '\n')
				extra++;

	cb.dlen = len + extra;
	buf = cb.data = nfmalloc( cb.dlen );
	i = 0;
	if (!CAP(UIDPLUS) && uid) {
		if (nocr) {
			for (; i < sbreak; i++)
				if (fmap[i] == '\n') {
					*buf++ = '\r';
					*buf++ = '\n';
				} else
					*buf++ = fmap[i];
		} else {
			memcpy( buf, fmap, sbreak );
			buf += sbreak;
		}
		memcpy( buf, "X-TUID: ", 8 );
		buf += 8;
		memcpy( buf, tuid, TUIDL * 2 );
		buf += TUIDL * 2;
		*buf++ = '\r';
		*buf++ = '\n';
		i = ebreak;
	}
	if (nocr) {
		for (; i < len; i++)
			if (fmap[i] == '\n') {
				*buf++ = '\r';
				*buf++ = '\n';
			} else
				*buf++ = fmap[i];
	} else
		memcpy( buf, fmap + i, len - i );

	free( fmap );

	d = 0;
	if (data->flags) {
		d = imap_make_flags( data->flags, flagstr );
		flagstr[d++] = ' ';
	}
	flagstr[d] = 0;

	if (!uid) {
		box = gctx->conf->trash;
		prefix = ctx->prefix;
		cb.create = 1;
		if (ctx->trashnc)
			imap->caps = imap->rcaps & ~(1 << LITERALPLUS);
	} else {
		box = gctx->name;
		prefix = !strcmp( box, "INBOX" ) ? "" : ctx->prefix;
		cb.create = (gctx->opts & OPEN_CREATE) != 0;
		/*if (ctx->currentnc)
			imap->caps = imap->rcaps & ~(1 << LITERALPLUS);*/
	}
	cb.ctx = uid;
	ret = imap_exec_m( ctx, &cb, "APPEND \"%s%s\" %s", prefix, box, flagstr );
	imap->caps = imap->rcaps;
	if (ret != DRV_OK)
		return ret;
	if (!uid)
		ctx->trashnc = 0;
	else {
		/*ctx->currentnc = 0;*/
		gctx->count++;
	}

	if (CAP(UIDPLUS) || !uid)
		return DRV_OK;

	/* Didn't receive an APPENDUID */
	cb.uid = -1; /* we're looking for a UID */
	cb.data = 0; /* reset; ctx still set */
	return imap_exec_m( ctx, &cb, "UID SEARCH HEADER X-TUID %s", tuid );
}

static int
imap_list( store_t *gctx, string_list_t **retb )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	imap_t *imap = ctx->imap;
	int ret;

	imap->boxes = 0;
	if ((ret = imap_exec_b( ctx, 0, "LIST \"\" \"%s%%\"", ctx->prefix )) != DRV_OK)
		return ret;
	*retb = imap->boxes;
	return DRV_OK;
}

static int
imap_check( store_t *gctx )
{
	(void) gctx;
	/* flush queue here */
	return DRV_OK;
}

imap_server_conf_t *servers, **serverapp = &servers;

static int
imap_parse_store( conffile_t *cfg, store_conf_t **storep, int *err )
{
	imap_store_conf_t *store;
	imap_server_conf_t *server, *srv, sserver;

	if (!strcasecmp( "IMAPAccount", cfg->cmd )) {
		server = nfcalloc( sizeof(*server) );
		server->name = nfstrdup( cfg->val );
		*serverapp = server;
		serverapp = &server->next;
		store = 0;
	} else if (!strcasecmp( "IMAPStore", cfg->cmd )) {
		store = nfcalloc( sizeof(*store) );
		store->gen.driver = &imap_driver;
		store->gen.name = nfstrdup( cfg->val );
		store->use_namespace = 1;
		memset( &sserver, 0, sizeof(sserver) );
		server = &sserver;
	} else
		return 0;

#if HAVE_LIBSSL
	/* this will probably annoy people, but its the best default just in
	 * case people forget to turn it on
	 */
	server->require_ssl = 1;
	server->use_tlsv1 = 1;
#endif

	while (getcline( cfg ) && cfg->cmd) {
		if (!strcasecmp( "Account", cfg->cmd )) {
			for (srv = servers; srv; srv = srv->next)
				if (srv->name && !strcmp( srv->name, cfg->val ))
					goto gotsrv;
			fprintf( stderr, "%s:%d: unknown IMAP account '%s'\n",
			         cfg->file, cfg->line, cfg->val );
			*err = 1;
			continue;
		  gotsrv:
			store->server = srv;
		} else if (!strcasecmp( "Host", cfg->cmd )) {
#if HAVE_LIBSSL
			if (!memcmp( "imaps:", cfg->val, 6 )) {
				cfg->val += 6;
				server->use_imaps = 1;
				server->use_sslv2 = 1;
				server->use_sslv3 = 1;
				if (!server->port)
					server->port = 993;
			} else
#endif
			{
				if (!memcmp( "imap:", cfg->val, 5 ))
					cfg->val += 5;
				if (!server->port)
					server->port = 143;
			}
			if (!memcmp( "//", cfg->val, 2 ))
				cfg->val += 2;
			server->host = nfstrdup( cfg->val );
		}
		else if (!strcasecmp( "User", cfg->cmd ))
			server->user = nfstrdup( cfg->val );
		else if (!strcasecmp( "Pass", cfg->cmd ))
			server->pass = nfstrdup( cfg->val );
		else if (!strcasecmp( "Port", cfg->cmd ))
			server->port = parse_int( cfg );
#if HAVE_LIBSSL
		else if (!strcasecmp( "CertificateFile", cfg->cmd ))
			server->cert_file = expand_strdup( cfg->val );
		else if (!strcasecmp( "RequireSSL", cfg->cmd ))
			server->require_ssl = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv2", cfg->cmd ))
			server->use_sslv2 = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv3", cfg->cmd ))
			server->use_sslv3 = parse_bool( cfg );
		else if (!strcasecmp( "UseTLSv1", cfg->cmd ))
			server->use_tlsv1 = parse_bool( cfg );
		else if (!strcasecmp( "RequireCRAM", cfg->cmd ))
			server->require_cram = parse_bool( cfg );
#endif
		else if (!strcasecmp( "Tunnel", cfg->cmd ))
			server->tunnel = nfstrdup( cfg->val );
		else if (store) {
			if (!strcasecmp( "UseNamespace", cfg->cmd ))
				store->use_namespace = parse_bool( cfg );
			else if (!strcasecmp( "Path", cfg->cmd ))
				store->gen.path = nfstrdup( cfg->val );
			else
				parse_generic_store( &store->gen, cfg, err );
		} else {
			fprintf( stderr, "%s:%d: unknown keyword '%s'\n",
			         cfg->file, cfg->line, cfg->cmd );
			*err = 1;
		}
	}
	if (!store || !store->server) {
		if (!server->tunnel && !server->host) {
			if (store)
				fprintf( stderr, "IMAP store '%s' has incomplete connection details\n", store->gen.name );
			else
				fprintf( stderr, "IMAP account '%s' has incomplete connection details\n", server->name );
			*err = 1;
			/* leaking server/store */
			*storep = 0;
			return 1;
		}
	}
	*storep = &store->gen;
	if (store && !store->server) {
		store->server = nfmalloc( sizeof(sserver) );
		memcpy( store->server, &sserver, sizeof(sserver) );
	}
	return 1;
}

struct driver imap_driver = {
	imap_parse_store,
	imap_open_store,
	imap_close_store,
	imap_list,
	imap_prepare,
	imap_select,
	imap_fetch_msg,
	imap_store_msg,
	imap_set_flags,
	imap_trash_msg,
	imap_check,
	imap_close
};
