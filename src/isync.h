/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>
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

#define _GNU_SOURCE

#include <config.h>

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#define as(ar) (sizeof(ar)/sizeof(ar[0]))

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define ATTR_UNUSED __attribute__((unused))
# define ATTR_NORETURN __attribute__((noreturn))
# define ATTR_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
#else
# define ATTR_UNUSED
# define ATTR_NORETURN
# define ATTR_PRINTFLIKE(fmt,var)
#endif

#define EXE "mbsync"

typedef struct {
	const char *file;
	FILE *fp;
	char *buf;
	int bufl;
	int line;
	char *cmd, *val, *rest;
} conffile_t;

#define OP_NEW             (1<<0)
#define OP_RENEW           (1<<1)
#define OP_DELETE          (1<<2)
#define OP_FLAGS           (1<<3)
#define  OP_MASK_TYPE      (OP_NEW|OP_RENEW|OP_DELETE|OP_FLAGS) /* asserted in the target ops */
#define OP_EXPUNGE         (1<<4)
#define OP_CREATE          (1<<5)
#define XOP_PUSH           (1<<6)
#define XOP_PULL           (1<<7)
#define  XOP_MASK_DIR      (XOP_PUSH|XOP_PULL)
#define XOP_HAVE_TYPE      (1<<8)
#define XOP_HAVE_EXPUNGE   (1<<9)
#define XOP_HAVE_CREATE    (1<<10)

typedef struct driver driver_t;

typedef struct store_conf {
	struct store_conf *next;
	char *name;
	driver_t *driver;
	const char *path; /* should this be here? its interpretation is driver-specific */
	char *map_inbox;
	char *trash;
	unsigned max_size; /* off_t is overkill */
	unsigned trash_remote_new:1, trash_only_new:1;
} store_conf_t;

typedef struct string_list {
	struct string_list *next;
	char string[1];
} string_list_t;

typedef struct channel_conf {
	struct channel_conf *next;
	char *name;
	store_conf_t *master, *slave;
	char *master_name, *slave_name;
	char *sync_state;
	string_list_t *patterns;
	int mops, sops;
	unsigned max_messages; /* for slave only */
} channel_conf_t;

typedef struct group_conf {
	struct group_conf *next;
	char *name;
	string_list_t *channels;
} group_conf_t;

/* For message->flags */
/* Keep the mailbox driver flag definitions in sync! */
/* The order is according to alphabetical maildir flag sort */
#define F_DRAFT	     (1<<0) /* Draft */
#define F_FLAGGED    (1<<1) /* Flagged */
#define F_ANSWERED   (1<<2) /* Replied */
#define F_SEEN       (1<<3) /* Seen */
#define F_DELETED    (1<<4) /* Trashed */
#define NUM_FLAGS 5

/* For message->status */
#define M_RECENT       (1<<0) /* unsyncable flag; maildir_* depend on this being 1<<0 */
#define M_DEAD         (1<<1) /* expunged */
#define M_FLAGS        (1<<2) /* flags fetched */
#define M_PROCESSED    (1<<3) /* registered in pair */
#define M_NOT_SYNCED   (1<<4) /* not in remote mailbox, yet */
#define M_EXPIRED      (1<<5) /* kicked out by MaxMessages */

typedef struct message {
	struct message *next;
	/* string_list_t *keywords; */
	size_t size; /* zero implies "not fetched" */
	int uid;
	unsigned char flags, status;
} message_t;

/* For opts, both in store and driver_t->select() */
#define OPEN_OLD        (1<<0)
#define OPEN_NEW        (1<<1)
#define OPEN_FLAGS      (1<<2)
#define OPEN_SIZE       (1<<3)
#define OPEN_CREATE     (1<<4)
#define OPEN_EXPUNGE    (1<<5)
#define OPEN_SETFLAGS   (1<<6)
#define OPEN_APPEND     (1<<7)

typedef struct store {
	store_conf_t *conf; /* foreign */

	/* currently open mailbox */
	const char *name; /* foreign! maybe preset? */
	char *path; /* own */
	message_t *msgs; /* own */
	int uidvalidity;
	unsigned char opts; /* maybe preset? */
	/* note that the following do _not_ reflect stats from msgs, but mailbox totals */
	int count; /* # of messages */
	int recent; /* # of recent messages - don't trust this beyond the initial read */
} store_t;

typedef struct {
	char *data;
	int len;
	unsigned char flags;
	unsigned char crlf:1;
} msg_data_t;

#define DRV_OK          0
#define DRV_MSG_BAD     -1
#define DRV_BOX_BAD     -2
#define DRV_STORE_BAD   -3

struct driver {
	int (*parse_store)( conffile_t *cfg, store_conf_t **storep, int *err );
	store_t *(*open_store)( store_conf_t *conf, store_t *oldctx );
	void (*close_store)( store_t *ctx );
	int (*list)( store_t *ctx, string_list_t **boxes );
	void (*prepare)( store_t *ctx, int opts );
	int (*select)( store_t *ctx, int minuid, int maxuid, int *excs, int nexcs );
	int (*fetch_msg)( store_t *ctx, message_t *msg, msg_data_t *data );
	int (*store_msg)( store_t *ctx, msg_data_t *data, int *uid ); /* if uid is null, store to trash */
	int (*set_flags)( store_t *ctx, message_t *msg, int uid, int add, int del ); /* msg can be null, therefore uid as a fallback */
	int (*trash_msg)( store_t *ctx, message_t *msg ); /* This may expunge the original message immediately, but it needn't to */
	int (*check)( store_t *ctx ); /* IMAP-style: flush */
	int (*close)( store_t *ctx ); /* IMAP-style: expunge inclusive */
};


/* main.c */

extern int Pid;
extern char Hostname[256];
extern const char *Home;


/* util.c */

extern int Verbose, Quiet, Debug;

void debug( const char *, ... );
void info( const char *, ... );
void infoc( char );
void warn( const char *, ... );

char *next_arg( char ** );

void add_string_list( string_list_t **list, const char *str );
void free_string_list( string_list_t *list );

void free_generic_messages( message_t * );

void strip_cr( msg_data_t *msgdata );

void *nfmalloc( size_t sz );
void *nfcalloc( size_t sz );
void *nfrealloc( void *mem, size_t sz );
char *nfstrdup( const char *str );
int nfvasprintf( char **str, const char *fmt, va_list va );
int nfasprintf( char **str, const char *fmt, ... );
int nfsnprintf( char *buf, int blen, const char *fmt, ... );
void ATTR_NORETURN oob( void );

char *expand_strdup( const char *s );

void sort_ints( int *arr, int len );

void arc4_init( void );
unsigned char arc4_getbyte( void );

/* sync.c */

#define SYNC_OK           0
#define SYNC_FAIL         1
#define SYNC_MASTER_BAD   2
#define SYNC_SLAVE_BAD    3

int sync_boxes( store_t *, const char *,
                store_t *, const char *,
                channel_conf_t * );

/* config.c */

extern channel_conf_t *channels;
extern group_conf_t *groups;
extern int global_mops, global_sops;
extern char *global_sync_state;

int parse_bool( conffile_t *cfile );
int parse_int( conffile_t *cfile );
int parse_size( conffile_t *cfile );
int getcline( conffile_t *cfile );
int merge_ops( int cops, int *mops, int *sops );
int load_config( const char *filename, int pseudo );
void parse_generic_store( store_conf_t *store, conffile_t *cfg, int *err );

/* drv_*.c */
extern driver_t maildir_driver, imap_driver;
