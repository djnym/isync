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

#include <sys/types.h>
#include <stdarg.h>
#if HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

typedef struct
{
    int fd;
#if HAVE_LIBSSL
    SSL *ssl;
    unsigned int use_ssl:1;
#endif
} Socket_t;

typedef struct
{
    Socket_t *sock;
    char buf[1024];
    int bytes;
    int offset;
}
buffer_t;

typedef struct config config_t;
typedef struct mailbox mailbox_t;
typedef struct message message_t;

struct config
{
    char *maildir;
    char *path;	/* path relative to .maildir, or absolute path */
    char *host;
    int port;
    char *user;
    char *pass;
    char *box;
    char *alias;
    char *copy_deleted_to;
    int poll;	/* how often to poll (in seconds)  0 = OFF */
    off_t max_size;
    config_t *next;
#if HAVE_LIBSSL
    char *cert_file;
    unsigned int use_imaps:1;
    unsigned int require_ssl:1;
    unsigned int use_sslv2:1;
    unsigned int use_sslv3:1;
    unsigned int use_tlsv1:1;
    unsigned int require_cram:1;
#endif
    unsigned int use_namespace:1;
    unsigned int expunge:1;
    unsigned int delete:1;
};

/* struct representing local mailbox file */
struct mailbox
{
    char *path;
    message_t *msgs;
    unsigned int deleted;	/* # of deleted messages */
    unsigned int uidvalidity;
    unsigned int maxuid;	/* largest uid we know about */
    unsigned int changed:1;
    unsigned int maxuidchanged:1;
};

/* message dispositions */
#define D_SEEN		(1<<0)
#define D_ANSWERED	(1<<1)
#define D_DELETED	(1<<2)
#define D_FLAGGED	(1<<3)
#define D_RECENT	(1<<4)
#define D_DRAFT		(1<<5)
#define D_MAX		6

struct message
{
    char *file;
    unsigned int uid;
    unsigned int flags;
    unsigned int size;
    message_t *next;
    unsigned int processed:1;	/* message has already been evaluated */
    unsigned int new:1;		/* message is in the new/ subdir */
    unsigned int changed:1;	/* flags changed */
    unsigned int dead:1;	/* message doesn't exist on the server */
};

/* struct used for parsing IMAP lists */
typedef struct _list list_t;

#define NIL	(void*)0x1
#define LIST	(void*)0x2

struct _list {
    char *val;
    list_t *next;
    list_t *child;
};

/* imap connection info */
typedef struct
{
    Socket_t *sock;
    unsigned int count;		/* # of msgs */
    unsigned int recent;	/* # of recent messages */
    buffer_t *buf;		/* input buffer for reading server output */
    message_t *msgs;		/* list of messages on the server */
    config_t *box;		/* mailbox to open */
    char *prefix;		/* namespace prefix */
    unsigned int deleted;	/* # of deleted messages */
    unsigned int uidvalidity;
    unsigned int maxuid;
    unsigned int minuid;
    /* NAMESPACE info */
    list_t *ns_personal;
    list_t *ns_other;
    list_t *ns_shared;
    unsigned int have_namespace:1;
#if HAVE_LIBSSL
    unsigned int have_cram:1;
    unsigned int have_starttls:1;
    unsigned int cram:1;
#endif
}
imap_t;

/* flags for sync_mailbox */
#define	SYNC_DELETE	(1<<0)	/* delete local that don't exist on server */
#define SYNC_EXPUNGE	(1<<1)	/* don't fetch deleted messages */

extern config_t global;
extern config_t *boxes;
extern unsigned int Tag;
extern char Hostname[256];
extern int Verbose;

#if HAVE_LIBSSL
extern SSL_CTX *SSLContext;

char *cram (const char *, const char *, const char *);
#endif

char *next_arg (char **);

int sync_mailbox (mailbox_t *, imap_t *, int, unsigned int);

void config_defaults (config_t *);
void load_config (const char *);
char * expand_strdup (const char *s);
config_t *find_box (const char *);

void imap_close (imap_t *);
int imap_copy_message (imap_t * imap, unsigned int uid, const char *mailbox);
int imap_fetch_message (imap_t *, unsigned int, int);
int imap_set_flags (imap_t *, unsigned int, unsigned int);
int imap_expunge (imap_t *);
imap_t *imap_open (config_t *, unsigned int, imap_t *);
int imap_append_message (imap_t *, int, message_t *);

mailbox_t *maildir_open (const char *, int fast);
int maildir_expunge (mailbox_t *, int);
int maildir_sync (mailbox_t *);
int maildir_set_uidvalidity (mailbox_t *, unsigned int uidvalidity);
void maildir_close (mailbox_t *);

message_t * find_msg (message_t * list, unsigned int uid);
void free_message (message_t *);

/* parse an IMAP list construct */
list_t * parse_list (char *s, char **end);
int is_atom (list_t *list);
int is_list (list_t *list);
int is_nil (list_t *list);
void free_list (list_t *list);

#define strfcpy(a,b,c) {strncpy(a,b,c);(a)[c-1]=0;}
