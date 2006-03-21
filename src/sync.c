/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006 Oswald Buddenhagen <ossi@users.sf.net>
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
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * As a special exception, mbsync may be linked with the OpenSSL library,
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

const char *str_ms[] = { "master", "slave" }, *str_hl[] = { "push", "pull" };

void
Fclose( FILE *f )
{
	if (fclose( f ) == EOF) {
		perror( "cannot close file" );
		exit( 1 );
	}
}

void
Fprintf( FILE *f, const char *msg, ... )
{
	int r;
	va_list va;

	va_start( va, msg );
	r = vfprintf( f, msg, va );
	va_end( va );
	if (r < 0) {
		perror( "cannot write file" );
		exit( 1 );
	}
}


static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static int
parse_flags( const char *buf )
{
	unsigned flags, i, d;

	for (flags = i = d = 0; i < as(Flags); i++)
		if (buf[d] == Flags[i]) {
			flags |= (1 << i);
			d++;
		}
	return flags;
}

static int
make_flags( int flags, char *buf )
{
	unsigned i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return d;
}

#define S_DEAD         (1<<0)
#define S_DONE         (1<<1)
#define S_DEL(ms)      (1<<(2+(ms)))
#define S_EXPIRED      (1<<4)
#define S_EXPIRE       (1<<5)
#define S_NEXPIRE      (1<<6)
#define S_EXP_S        (1<<7)

#define mvBit(in,ib,ob) ((unsigned char)(((unsigned)in) * (ob) / (ib)))

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	int uid[2];
	message_t *msg[2];
	unsigned char status, flags, aflags[2], dflags[2];
	char tuid[TUIDL];
} sync_rec_t;

static int
select_box( sync_rec_t *srecs, store_t *ctx[], int maxuid[], int uidval[], int t, int minwuid, int *mexcs, int nmexcs, FILE *jfp )
{
	sync_rec_t *srec, *nsrec = 0;
	message_t *msg;
	const char *diag;
	int uid, maxwuid;
	char fbuf[16]; /* enlarge when support for keywords is added */

	if (ctx[t]->opts & OPEN_NEW) {
		if (minwuid > maxuid[t] + 1)
			minwuid = maxuid[t] + 1;
		maxwuid = INT_MAX;
	} else if (ctx[t]->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = srecs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->uid[t] > maxwuid)
				maxwuid = srec->uid[t];
	} else
		maxwuid = 0;
	infon( "Selecting %s %s... ", str_ms[t], ctx[t]->name );
	debug( maxwuid == INT_MAX ? "selecting %s [%d,inf]\n" : "selecting %s [%d,%d]\n", str_ms[t], minwuid, maxwuid );
	switch (ctx[t]->conf->driver->select( ctx[t], minwuid, maxwuid, mexcs, nmexcs )) {
	case DRV_STORE_BAD: return SYNC_BAD(t);
	case DRV_BOX_BAD: return SYNC_FAIL;
	}
	if (uidval[t] && uidval[t] != ctx[t]->uidvalidity) {
		error( "Error: UIDVALIDITY of %s changed (got %d, expected %d)\n", str_ms[t], ctx[t]->uidvalidity, uidval[t] );
		return SYNC_FAIL;
	}
	info( "%d messages, %d recent\n", ctx[M]->count, ctx[M]->recent );

	if (jfp) {
		/*
		 * Alternatively, the TUIDs could be fetched into the messages and
		 * looked up here. This would make the search faster (probably) and
		 * save roundtrips. On the downside, quite some additional data would
		 * have to be fetched for every message and the IMAP driver would be
		 * more complicated. This is a corner case anyway, so why bother.
		 */
		debug( "finding previously copied messages\n" );
		for (srec = srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == -2 && srec->tuid[0]) {
				debug( "  pair(%d,%d): lookup %s, TUID %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], str_ms[t], srec->tuid );
				switch (ctx[t]->conf->driver->find_msg( ctx[t], srec->tuid, &uid )) {
				case DRV_STORE_BAD: return SYNC_BAD(t);
				case DRV_OK:
					debug( "  -> new UID %d\n", uid );
					Fprintf( jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
					srec->uid[t] = uid;
					srec->tuid[0] = 0;
					break;
				default:
					debug( "  -> TUID lost\n" );
					Fprintf( jfp, "& %d %d\n", srec->uid[M], srec->uid[S] );
					srec->flags = 0;
					srec->tuid[0] = 0;
					break;
				}
			}
		}
	}

	/*
	 * Mapping msg -> srec (this variant) is dog slow for new messages.
	 * Mapping srec -> msg is dog slow for deleted messages.
	 * One solution would be using binary search on an index array.
	 * msgs are already sorted by UID, srecs would have to be sorted by uid[t].
	 */
	debug( "matching messages against sync records\n" );
	for (msg = ctx[t]->msgs; msg; msg = msg->next) {
		uid = msg->uid;
		if (DFlags & DEBUG) {
			make_flags( msg->flags, fbuf );
			printf( ctx[t]->opts & OPEN_SIZE ? "  message %5d, %-4s, %6d: " : "  message %5d, %-4s: ", uid, fbuf, msg->size );
		}
		for (srec = nsrec; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == uid) {
				diag = srec == nsrec ? "adjacently" : "after gap";
				goto found;
			}
		}
		for (srec = srecs; srec != nsrec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == uid) {
				diag = "after reset";
				goto found;
			}
		}
		msg->srec = 0;
		debug( "new\n" );
		continue;
	  found:
		msg->srec = srec;
		srec->msg[t] = msg;
		nsrec = srec->next;
		debug( "pairs %5d %s\n", srec->uid[1-t], diag );
	}

	return SYNC_OK;
}

static int
copy_msg( store_t *ctx[], int t, message_t *tmsg, const char *tuid, int *uid )
{
	msg_data_t msgdata;
	char *fmap, *buf;
	int i, len, extra, cra, crd, scr, tcr;
	int start, sbreak = 0, ebreak = 0;
	char c;

	msgdata.flags = tmsg->flags;
	switch (ctx[1-t]->conf->driver->fetch_msg( ctx[1-t], tmsg, &msgdata )) {
	case DRV_STORE_BAD: return SYNC_BAD(1-t);
	case DRV_BOX_BAD: return SYNC_FAIL;
	case DRV_MSG_BAD: return SYNC_NOGOOD;
	}
	tmsg->flags = msgdata.flags;

	scr = (ctx[1-t]->conf->driver->flags / DRV_CRLF) & 1;
	tcr = (ctx[t]->conf->driver->flags / DRV_CRLF) & 1;
	if (tuid || scr != tcr) {
		fmap = msgdata.data;
		len = msgdata.len;
		cra = crd = 0;
		if (scr > tcr)
			crd = -1;
		else if (scr < tcr)
			crd = 1;
		extra = 0, i = 0;
		if (tuid) {
			extra += 8 + TUIDL + 1 + tcr;
		  nloop:
			start = i;
			while (i < len) {
				c = fmap[i++];
				if (c == '\r')
					extra += crd;
				else if (c == '\n') {
					extra += cra;
					if (i - 2 + !scr == start) {
						sbreak = ebreak = i - 2 + !scr; // precalc this!
						goto oke;
					}
					if (!memcmp( fmap + start, "X-TUID: ", 8 )) {
						extra -= (ebreak = i) - (sbreak = start);
						goto oke;
					}
					goto nloop;
				}
			}
			/* invalid message */
			free( fmap );
			return SYNC_NOGOOD;
		}
	  oke:
		if (cra || crd)
			for (; i < len; i++) {
				c = fmap[i];
				if (c == '\r')
					extra += crd;
				else if (c == '\n')
					extra += cra;
			}

		msgdata.len = len + extra;
		buf = msgdata.data = nfmalloc( msgdata.len );
		i = 0;
		if (tuid) {
			if (cra) {
				for (; i < sbreak; i++) {
					if (fmap[i] == '\n')
						*buf++ = '\r';
					*buf++ = fmap[i];
				}
			} else if (crd) {
				for (; i < sbreak; i++)
					if (fmap[i] != '\r')
						*buf++ = fmap[i];
			} else {
				memcpy( buf, fmap, sbreak );
				buf += sbreak;
			}
			memcpy( buf, "X-TUID: ", 8 );
			buf += 8;
			memcpy( buf, tuid, TUIDL );
			buf += TUIDL;
			if (tcr)
				*buf++ = '\r';
			*buf++ = '\n';
			i = ebreak;
		}
		if (cra) {
			for (; i < len; i++) {
				if (fmap[i] == '\n')
					*buf++ = '\r';
				*buf++ = fmap[i];
			}
		} else if (crd) {
			for (; i < len; i++)
				if (fmap[i] != '\r')
					*buf++ = fmap[i];
		} else
			memcpy( buf, fmap + i, len - i );

		free( fmap );
	}

	switch (ctx[t]->conf->driver->store_msg( ctx[t], &msgdata, uid )) {
	case DRV_STORE_BAD: return SYNC_BAD(t);
	case DRV_OK: return SYNC_OK;
	default: return SYNC_FAIL;
	}
}

/* cases:
   a) both non-null
   b) only master null
   b.1) uid[M] 0
   b.2) uid[M] -1
   b.3) master not scanned
   b.4) master gone
   c) only slave null
   c.1) uid[S] 0
   c.2) uid[S] -1
   c.3) slave not scanned
   c.4) slave gone
   d) both null
   d.1) both gone
   d.2) uid[M] 0, slave not scanned
   d.3) uid[M] -1, slave not scanned
   d.4) master gone, slave not scanned
   d.5) uid[M] 0, slave gone
   d.6) uid[M] -1, slave gone
   d.7) uid[S] 0, master not scanned
   d.8) uid[S] -1, master not scanned
   d.9) slave gone, master not scanned
   d.10) uid[S] 0, master gone
   d.11) uid[S] -1, master gone
   impossible cases: both uid[M] & uid[S] 0 or -1, both not scanned
*/

typedef struct {
	char *dname, *jname, *nname, *lname;
	FILE *jfp, *nfp;
	sync_rec_t *srecs, **srecadd, **osrecadd;
	channel_conf_t *chan;
	store_t *ctx[2];
	driver_t *drv[2];
	int state[2], ret;
	int maxuid[2], uidval[2], smaxxuid, lfd;
} sync_vars_t;

#define ST_DID_EXPUNGE     (1<<16)

static char *
clean_strdup( const char *s )
{
	char *cs;
	int i;

	cs = nfstrdup( s );
	for (i = 0; cs[i]; i++)
		if (cs[i] == '/')
			cs[i] = '!';
	return cs;
}

#define JOURNAL_VERSION "2"

int
sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan )
{
	sync_vars_t svars[1];
	message_t *tmsg;
	sync_rec_t *srec, *nsrec;
	char *s, *cmname, *csname;
	FILE *jfp;
	int no[2], del[2], nex, minwuid, uid, nmsgs;
	int todel, *mexcs, nmexcs, rmexcs;
	int opts[2], line, t1, t2, t3, t;
	unsigned char nflags, sflags, aflags, dflags;
	struct stat st;
	struct flock lck;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[64];

	memset( svars, 0, sizeof(svars[0]) );
	svars->ctx[0] = ctx[0];
	svars->ctx[1] = ctx[1];
	svars->chan = chan;
	svars->srecadd = &svars->srecs;

	for (t = 0; t < 2; t++) {
		ctx[t]->name =
			(!names[t] || (ctx[t]->conf->map_inbox && !strcmp( ctx[t]->conf->map_inbox, names[t] ))) ?
				"INBOX" : names[t];
		ctx[t]->uidvalidity = 0;
		svars->drv[t] = ctx[t]->conf->driver;
		svars->drv[t]->prepare_paths( ctx[t] );
	}

	if (!strcmp( chan->sync_state ? chan->sync_state : global_sync_state, "*" )) {
		if (!ctx[S]->path) {
			error( "Error: store '%s' does not support in-box sync state\n", chan->stores[S]->name );
			return SYNC_BAD(S);
		}
		nfasprintf( &svars->dname, "%s/." EXE "state", ctx[S]->path );
	} else {
		csname = clean_strdup( ctx[S]->name );
		if (chan->sync_state)
			nfasprintf( &svars->dname, "%s%s", chan->sync_state, csname );
		else {
			cmname = clean_strdup( ctx[M]->name );
			nfasprintf( &svars->dname, "%s:%s:%s_:%s:%s", global_sync_state,
			            chan->stores[M]->name, cmname, chan->stores[S]->name, csname );
			free( cmname );
		}
		free( csname );
	}
	if (!(s = strrchr( svars->dname, '/' ))) {
		error( "Error: invalid SyncState '%s'\n", svars->dname );
		free( svars->dname );
		return SYNC_BAD(S);
	}
	*s = 0;
	if (mkdir( svars->dname, 0700 ) && errno != EEXIST) {
		error( "Error: cannot create SyncState directory '%s': %s\n", svars->dname, strerror(errno) );
		free( svars->dname );
		return SYNC_BAD(S);
	}
	*s = '/';
	nfasprintf( &svars->jname, "%s.journal", svars->dname );
	nfasprintf( &svars->nname, "%s.new", svars->dname );
	nfasprintf( &svars->lname, "%s.lock", svars->dname );
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	if ((svars->lfd = open( svars->lname, O_WRONLY|O_CREAT, 0666 )) < 0) {
		error( "Error: cannot create lock file %s: %s\n", svars->lname, strerror(errno) );
		svars->ret = SYNC_FAIL;
		goto bail2;
	}
	if (fcntl( svars->lfd, F_SETLK, &lck )) {
		error( "Error: channel :%s:%s-:%s:%s is locked\n",
		         chan->stores[M]->name, ctx[M]->name, chan->stores[S]->name, ctx[S]->name );
		svars->ret = SYNC_FAIL;
		goto bail1;
	}
	if ((jfp = fopen( svars->dname, "r" ))) {
		debug( "reading sync state %s ...\n", svars->dname );
		if (!fgets( buf, sizeof(buf), jfp ) || !(t = strlen( buf )) || buf[t - 1] != '\n') {
			error( "Error: incomplete sync state header in %s\n", svars->dname );
			fclose( jfp );
			svars->ret = SYNC_FAIL;
			goto bail;
		}
		if (sscanf( buf, "%d:%d %d:%d:%d", &svars->uidval[M], &svars->maxuid[M], &svars->uidval[S], &svars->smaxxuid, &svars->maxuid[S]) != 5) {
			error( "Error: invalid sync state header in %s\n", svars->dname );
			fclose( jfp );
			svars->ret = SYNC_FAIL;
			goto bail;
		}
		line = 1;
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete sync state entry at %s:%d\n", svars->dname, line );
				fclose( jfp );
				svars->ret = SYNC_FAIL;
				goto bail;
			}
			fbuf[0] = 0;
			if (sscanf( buf, "%d %d %15s", &t1, &t2, fbuf ) < 2) {
				error( "Error: invalid sync state entry at %s:%d\n", svars->dname, line );
				fclose( jfp );
				svars->ret = SYNC_FAIL;
				goto bail;
			}
			srec = nfmalloc( sizeof(*srec) );
			srec->uid[M] = t1;
			srec->uid[S] = t2;
			s = fbuf;
			if (*s == 'X') {
				s++;
				srec->status = S_EXPIRE | S_EXPIRED;
			} else
				srec->status = 0;
			srec->flags = parse_flags( s );
			debug( "  entry (%d,%d,%u,%s)\n", srec->uid[M], srec->uid[S], srec->flags, srec->status & S_EXPIRED ? "X" : "" );
			srec->msg[M] = srec->msg[S] = 0;
			srec->tuid[0] = 0;
			srec->next = 0;
			*svars->srecadd = srec;
			svars->srecadd = &srec->next;
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			error( "Error: cannot read sync state %s\n", svars->dname );
			svars->ret = SYNC_FAIL;
			goto bail;
		}
	}
	line = 0;
	if ((jfp = fopen( svars->jname, "r" ))) {
		if (!stat( svars->nname, &st ) && fgets( buf, sizeof(buf), jfp )) {
			debug( "recovering journal ...\n" );
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete journal header in %s\n", svars->jname );
				fclose( jfp );
				svars->ret = SYNC_FAIL;
				goto bail;
			}
			if (memcmp( buf, JOURNAL_VERSION "\n", strlen(JOURNAL_VERSION) + 1 )) {
				error( "Error: incompatible journal version "
				                 "(got %.*s, expected " JOURNAL_VERSION ")\n", t - 1, buf );
				fclose( jfp );
				svars->ret = SYNC_FAIL;
				goto bail;
			}
			srec = 0;
			line = 1;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
					error( "Error: incomplete journal entry at %s:%d\n", svars->jname, line );
					fclose( jfp );
					svars->ret = SYNC_FAIL;
					goto bail;
				}
				if (buf[0] == '#' ?
				      (t3 = 0, (sscanf( buf + 2, "%d %d %n", &t1, &t2, &t3 ) < 2) || !t3 || (t - t3 != TUIDL + 3)) :
				      buf[0] == '(' || buf[0] == ')' ?
				        (sscanf( buf + 2, "%d", &t1 ) != 1) :
				        buf[0] == '+' || buf[0] == '&' || buf[0] == '-' || buf[0] == '|' || buf[0] == '/' || buf[0] == '\\' ?
				          (sscanf( buf + 2, "%d %d", &t1, &t2 ) != 2) :
				          (sscanf( buf + 2, "%d %d %d", &t1, &t2, &t3 ) != 3))
				{
					error( "Error: malformed journal entry at %s:%d\n", svars->jname, line );
					fclose( jfp );
					svars->ret = SYNC_FAIL;
					goto bail;
				}
				if (buf[0] == '(')
					svars->maxuid[M] = t1;
				else if (buf[0] == ')')
					svars->maxuid[S] = t1;
				else if (buf[0] == '|') {
					svars->uidval[M] = t1;
					svars->uidval[S] = t2;
				} else if (buf[0] == '+') {
					srec = nfmalloc( sizeof(*srec) );
					srec->uid[M] = t1;
					srec->uid[S] = t2;
					debug( "  new entry(%d,%d)\n", t1, t2 );
					srec->msg[M] = srec->msg[S] = 0;
					srec->status = 0;
					srec->flags = 0;
					srec->tuid[0] = 0;
					srec->next = 0;
					*svars->srecadd = srec;
					svars->srecadd = &srec->next;
				} else {
					for (nsrec = srec; srec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					for (srec = svars->srecs; srec != nsrec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					error( "Error: journal entry at %s:%d refers to non-existing sync state entry\n", svars->jname, line );
					fclose( jfp );
					svars->ret = SYNC_FAIL;
					goto bail;
				  syncfnd:
					debugn( "  entry(%d,%d,%u) ", srec->uid[M], srec->uid[S], srec->flags );
					switch (buf[0]) {
					case '-':
						debug( "killed\n" );
						srec->status = S_DEAD;
						break;
					case '#':
						debug( "TUID now %." stringify(TUIDL) "s\n", buf + t3 + 2 );
						memcpy( srec->tuid, buf + t3 + 2, TUIDL );
						break;
					case '&':
						debug( "TUID %." stringify(TUIDL) "s lost\n", srec->tuid );
						srec->flags = 0;
						srec->tuid[0] = 0;
						break;
					case '<':
						debug( "master now %d\n", t3 );
						srec->uid[M] = t3;
						srec->tuid[0] = 0;
						break;
					case '>':
						debug( "slave now %d\n", t3 );
						srec->uid[S] = t3;
						srec->tuid[0] = 0;
						break;
					case '*':
						debug( "flags now %d\n", t3 );
						srec->flags = t3;
						break;
					case '~':
						debug( "expire now %d\n", t3 );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '\\':
						t3 = (srec->status & S_EXPIRED);
						debug( "expire back to %d\n", t3 / S_EXPIRED );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '/':
						t3 = (srec->status & S_EXPIRE);
						debug( "expired now %d\n", t3 / S_EXPIRE );
						if (t3) {
							if (svars->smaxxuid < srec->uid[S])
								svars->smaxxuid = srec->uid[S];
							srec->status |= S_EXPIRED;
						} else
							srec->status &= ~S_EXPIRED;
						break;
					default:
						error( "Error: unrecognized journal entry at %s:%d\n", svars->jname, line );
						fclose( jfp );
						svars->ret = SYNC_FAIL;
						goto bail;
					}
				}
			}
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			error( "Error: cannot read journal %s\n", svars->jname );
			svars->ret = SYNC_FAIL;
			goto bail;
		}
	}
	if (!(svars->nfp = fopen( svars->nname, "w" ))) {
		error( "Error: cannot write new sync state %s\n", svars->nname );
		svars->ret = SYNC_FAIL;
		goto bail;
	}
	if (!(svars->jfp = fopen( svars->jname, "a" ))) {
		error( "Error: cannot write journal %s\n", svars->jname );
		fclose( svars->nfp );
		svars->ret = SYNC_FAIL;
		goto bail;
	}
	setlinebuf( svars->jfp );
	if (!line)
		Fprintf( svars->jfp, JOURNAL_VERSION "\n" );

	opts[M] = opts[S] = 0;
	for (t = 0; t < 2; t++) {
		if (chan->ops[t] & (OP_DELETE|OP_FLAGS)) {
			opts[t] |= OPEN_SETFLAGS;
			opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_FLAGS)
				opts[1-t] |= OPEN_FLAGS;
		}
		if (chan->ops[t] & (OP_NEW|OP_RENEW)) {
			opts[t] |= OPEN_APPEND;
			if (chan->ops[t] & OP_RENEW)
				opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_NEW)
				opts[1-t] |= OPEN_NEW;
			if (chan->ops[t] & OP_EXPUNGE)
				opts[1-t] |= OPEN_FLAGS;
			if (chan->stores[t]->max_size)
				opts[1-t] |= OPEN_SIZE;
		}
		if (chan->ops[t] & OP_EXPUNGE) {
			opts[t] |= OPEN_EXPUNGE;
			if (chan->stores[t]->trash) {
				if (!chan->stores[t]->trash_only_new)
					opts[t] |= OPEN_OLD;
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
			} else if (chan->stores[1-t]->trash && chan->stores[1-t]->trash_remote_new)
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
		}
		if (chan->ops[t] & OP_CREATE)
			opts[t] |= OPEN_CREATE;
	}
	if ((chan->ops[S] & (OP_NEW|OP_RENEW)) && chan->max_messages)
		opts[S] |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	if (line)
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if ((mvBit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)
				opts[S] |= OPEN_OLD|OPEN_FLAGS;
			if (srec->tuid[0]) {
				if (srec->uid[M] == -2)
					opts[M] |= OPEN_OLD|OPEN_FIND;
				else if (srec->uid[S] == -2)
					opts[S] |= OPEN_OLD|OPEN_FIND;
			}
		}
	svars->drv[M]->prepare_opts( ctx[M], opts[M] );
	svars->drv[S]->prepare_opts( ctx[S], opts[S] );

	if ((svars->ret = select_box( svars->srecs, svars->ctx, svars->maxuid, svars->uidval, S, (ctx[S]->opts & OPEN_OLD) ? 1 : INT_MAX, 0, 0, line ? svars->jfp : 0 )) != SYNC_OK)
		goto finish;

	mexcs = 0;
	nmexcs = rmexcs = 0;
	minwuid = INT_MAX;
	if (svars->smaxxuid) {
		debug( "preparing master selection - max expired slave uid is %d\n", svars->smaxxuid );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXPIRED) {
				if (!srec->uid[S] || ((svars->ctx[S]->opts & OPEN_OLD) && !srec->msg[S])) {
					srec->status |= S_EXP_S;
					continue;
				}
			} else {
				if (svars->smaxxuid >= srec->uid[S])
					continue;
			}
			if (minwuid > srec->uid[M])
				minwuid = srec->uid[M];
		}
		debug( "  min non-orphaned master uid is %d\n", minwuid );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXP_S) {
				if (minwuid > srec->uid[M] && svars->maxuid[M] >= srec->uid[M]) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S]) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (minwuid > srec->uid[M]) {
				if (srec->uid[S] < 0) {
					if (svars->maxuid[M] >= srec->uid[M]) {
						debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
						srec->status = S_DEAD;
						Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
					}
				} else if (srec->uid[M] > 0 && srec->uid[S] && (svars->ctx[M]->opts & OPEN_OLD) &&
				           (!(svars->ctx[M]->opts & OPEN_NEW) || svars->maxuid[M] >= srec->uid[M])) {
					if (nmexcs == rmexcs) {
						rmexcs = rmexcs * 2 + 100;
						mexcs = nfrealloc( mexcs, rmexcs * sizeof(int) );
					}
					mexcs[nmexcs++] = srec->uid[M];
				}
			}
		}
		debugn( "  exception list is:" );
		for (t = 0; t < nmexcs; t++)
			debugn( " %d", mexcs[t] );
		debug( "\n" );
	} else if (ctx[M]->opts & OPEN_OLD)
		minwuid = 1;
	if ((svars->ret = select_box( svars->srecs, svars->ctx, svars->maxuid, svars->uidval, M, minwuid, mexcs, nmexcs, line ? svars->jfp : 0 )) != SYNC_OK)
		goto finish;

	if (!svars->uidval[M] || !svars->uidval[S]) {
		svars->uidval[M] = svars->ctx[M]->uidvalidity;
		svars->uidval[S] = svars->ctx[S]->uidvalidity;
		Fprintf( svars->jfp, "| %d %d\n", svars->uidval[M], svars->uidval[S] );
	}

	info( "Synchronizing...\n" );

	debug( "synchronizing new entries\n" );
	svars->osrecadd = svars->srecadd;
	for (t = 0; t < 2; t++) {
		for (nmsgs = 0, tmsg = svars->ctx[1-t]->msgs; tmsg; tmsg = tmsg->next)
			if (tmsg->srec ? tmsg->srec->uid[t] < 0 && (tmsg->srec->uid[t] == -1 ? (svars->chan->ops[t] & OP_RENEW) : (svars->chan->ops[t] & OP_NEW)) : (svars->chan->ops[t] & OP_NEW)) {
				debug( "new message %d on %s\n", tmsg->uid, str_ms[1-t] );
				if ((svars->chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED))
					debug( "  -> not %sing - would be expunged anyway\n", str_hl[t] );
				else {
					if (tmsg->srec) {
						srec = tmsg->srec;
						srec->status |= S_DONE;
						debug( "  -> pair(%d,%d) exists\n", srec->uid[M], srec->uid[S] );
					} else {
						srec = nfmalloc( sizeof(*srec) );
						srec->next = 0;
						*svars->srecadd = srec;
						svars->srecadd = &srec->next;
						srec->status = S_DONE;
						srec->flags = 0;
						srec->tuid[0] = 0;
						srec->uid[1-t] = tmsg->uid;
						srec->uid[t] = -2;
						Fprintf( svars->jfp, "+ %d %d\n", srec->uid[M], srec->uid[S] );
						debug( "  -> pair(%d,%d) created\n", srec->uid[M], srec->uid[S] );
					}
					if ((tmsg->flags & F_FLAGGED) || !svars->chan->stores[t]->max_size || tmsg->size <= svars->chan->stores[t]->max_size) {
						if (!nmsgs)
							infon( t ? "Pulling new messages..." : "Pushing new messages..." );
						else
							infoc( '.' );
						nmsgs++;
						if (tmsg->flags) {
							srec->flags = tmsg->flags;
							Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], srec->flags );
							debug( "  -> updated flags to %u\n", tmsg->flags );
						}
						for (t1 = 0; t1 < TUIDL; t1++) {
							t2 = arc4_getbyte() & 0x3f;
							srec->tuid[t1] = t2 < 26 ? t2 + 'A' : t2 < 52 ? t2 + 'a' - 26 : t2 < 62 ? t2 + '0' - 52 : t2 == 62 ? '+' : '/';
						}
						Fprintf( svars->jfp, "# %d %d %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], srec->tuid );
						debug( "  -> %sing message, TUID %." stringify(TUIDL) "s\n", str_hl[t], srec->tuid );
						switch ((svars->ret = copy_msg( svars->ctx, t, tmsg, srec->tuid, &uid ))) {
						case SYNC_OK: break;
						case SYNC_NOGOOD:
							/* The error is either transient or the message is gone. */
							debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
							srec->status = S_DEAD;
							Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
							continue;
						default: goto finish;
						}
					} else {
						if (tmsg->srec) {
							debug( "  -> not %sing - still too big\n", str_hl[t] );
							continue;
						}
						debug( "  -> not %sing - too big\n", str_hl[t] );
						uid = -1;
					}
					if (srec->uid[t] != uid) {
						debug( "  -> new UID %d\n", uid );
						Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
						srec->uid[t] = uid;
						srec->tuid[0] = 0;
					}
					if (!tmsg->srec) {
						tmsg->srec = srec;
						if (svars->maxuid[1-t] < tmsg->uid) {
							svars->maxuid[1-t] = tmsg->uid;
							Fprintf( svars->jfp, "%c %d\n", ")("[t], tmsg->uid );
						}
					}
				}
			}
		if (nmsgs)
			info( " %d messages\n", nmsgs );
	}
	debug( "finding just copied messages\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		if (srec->tuid[0]) {
			t = (srec->uid[M] == -2) ? M : S;
			debug( "  pair(%d,%d): lookup %s, TUID %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], str_ms[t], srec->tuid );
			switch (svars->drv[t]->find_msg( svars->ctx[t], srec->tuid, &uid )) {
			case DRV_STORE_BAD: svars->ret = SYNC_BAD(t); goto finish;
			case DRV_OK:
				debug( "  -> new UID %d\n", uid );
				break;
			default:
				warn( "Warning: cannot find newly stored message %." stringify(TUIDL) "s on %s.\n", srec->tuid, str_ms[t] );
				uid = 0;
				break;
			}
			Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
			srec->uid[t] = uid;
			srec->tuid[0] = 0;
		}
	}

	debug( "synchronizing old entries\n" );
	for (srec = svars->srecs; srec != *svars->osrecadd; srec = srec->next) {
		if (srec->status & (S_DEAD|S_DONE))
			continue;
		debug( "pair (%d,%d)\n", srec->uid[M], srec->uid[S] );
		no[M] = !srec->msg[M] && (svars->ctx[M]->opts & OPEN_OLD);
		no[S] = !srec->msg[S] && (svars->ctx[S]->opts & OPEN_OLD);
		if (no[M] && no[S]) {
			debug( "  vanished\n" );
			/* d.1) d.5) d.6) d.10) d.11) */
			srec->status = S_DEAD;
			Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
		} else {
			del[M] = no[M] && (srec->uid[M] > 0);
			del[S] = no[S] && (srec->uid[S] > 0);

			for (t = 0; t < 2; t++) {
				srec->aflags[t] = srec->dflags[t] = 0;
				if (srec->msg[t] && (srec->msg[t]->flags & F_DELETED))
					srec->status |= S_DEL(t);
				/* excludes (push) c.3) d.2) d.3) d.4) / (pull) b.3) d.7) d.8) d.9) */
				if (!srec->uid[t]) {
					/* b.1) / c.1) */
					debug( "  no more %s\n", str_ms[t] );
				} else if (del[1-t]) {
					/* c.4) d.9) / b.4) d.4) */
					if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS) && srec->msg[t]->flags != srec->flags)
						info( "Info: conflicting changes in (%d,%d)\n", srec->uid[M], srec->uid[S] );
					if (svars->chan->ops[t] & OP_DELETE) {
						debug( "  %sing delete\n", str_hl[t] );
						switch (svars->drv[t]->set_flags( svars->ctx[t], srec->msg[t], srec->uid[t], F_DELETED, 0 )) {
						case DRV_STORE_BAD: svars->ret = SYNC_BAD(t); goto finish;
						case DRV_BOX_BAD: svars->ret = SYNC_FAIL; goto finish;
						default: /* ok */ break;
						case DRV_OK:
							srec->status |= S_DEL(t);
							Fprintf( svars->jfp, "%c %d %d 0\n", "><"[t], srec->uid[M], srec->uid[S] );
							srec->uid[1-t] = 0;
						}
					} else
						debug( "  not %sing delete\n", str_hl[t] );
				} else if (!srec->msg[1-t])
					/* c.1) c.2) d.7) d.8) / b.1) b.2) d.2) d.3) */
					;
				else if (srec->uid[t] < 0)
					/* b.2) / c.2) */
					; /* handled as new messages (sort of) */
				else if (!del[t]) {
					/* a) & b.3) / c.3) */
					if (svars->chan->ops[t] & OP_FLAGS) {
						sflags = srec->msg[1-t]->flags;
						if ((srec->status & (S_EXPIRE|S_EXPIRED)) && !t)
							sflags &= ~F_DELETED;
						srec->aflags[t] = sflags & ~srec->flags;
						srec->dflags[t] = ~sflags & srec->flags;
						if (DFlags & DEBUG) {
							char afbuf[16], dfbuf[16]; /* enlarge when support for keywords is added */
							make_flags( srec->aflags[t], afbuf );
							make_flags( srec->dflags[t], dfbuf );
							debug( "  %sing flags: +%s -%s\n", str_hl[t], afbuf, dfbuf );
						}
					} else
						debug( "  not %sing flags\n", str_hl[t] );
				} /* else b.4) / c.4) */
			}
		}
	}

	if ((svars->chan->ops[S] & (OP_NEW|OP_RENEW|OP_FLAGS)) && svars->chan->max_messages) {
		/* Flagged and not yet synced messages older than the first not
		 * expired message are not counted. */
		todel = svars->ctx[S]->count - svars->chan->max_messages;
		debug( "scheduling %d excess messages for expiration\n", todel );
		for (tmsg = svars->ctx[S]->msgs; tmsg && todel > 0; tmsg = tmsg->next)
			if (!(tmsg->status & M_DEAD) && (srec = tmsg->srec) &&
			    ((tmsg->flags | srec->aflags[S]) & ~srec->dflags[S] & F_DELETED) &&
			    !(srec->status & (S_EXPIRE|S_EXPIRED)))
				todel--;
		debug( "%d non-deleted excess messages\n", todel );
		for (tmsg = svars->ctx[S]->msgs; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			if (!(srec = tmsg->srec) || srec->uid[M] <= 0)
				todel--;
			else {
				nflags = (tmsg->flags | srec->aflags[S]) & ~srec->dflags[S];
				if (!(nflags & F_DELETED) || (srec->status & (S_EXPIRE|S_EXPIRED))) {
					if (nflags & F_FLAGGED)
						todel--;
					else if (!(tmsg->status & M_RECENT) &&
					         (todel > 0 ||
					          ((srec->status & (S_EXPIRE|S_EXPIRED)) == (S_EXPIRE|S_EXPIRED)) ||
					          ((srec->status & (S_EXPIRE|S_EXPIRED)) && (tmsg->flags & F_DELETED)))) {
						srec->status |= S_NEXPIRE;
						debug( "  pair(%d,%d)\n", srec->uid[M], srec->uid[S] );
						todel--;
					}
				}
			}
		}
		debug( "%d excess messages remain\n", todel );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if ((srec->status & (S_DEAD|S_DONE)) || !srec->msg[S])
				continue;
			nex = (srec->status / S_NEXPIRE) & 1;
			if (nex != ((srec->status / S_EXPIRED) & 1)) {
				if (nex != ((srec->status / S_EXPIRE) & 1)) {
					Fprintf( svars->jfp, "~ %d %d %d\n", srec->uid[M], srec->uid[S], nex );
					debug( "  pair(%d,%d): %d (pre)\n", srec->uid[M], srec->uid[S], nex );
					srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
				} else
					debug( "  pair(%d,%d): %d (pending)\n", srec->uid[M], srec->uid[S], nex );
			}
		}
	}

	debug( "synchronizing flags\n" );
	for (srec = svars->srecs; srec != *svars->osrecadd; srec = srec->next) {
		if (srec->status & (S_DEAD|S_DONE))
			continue;
		for (t = 0; t < 2; t++) {
			aflags = srec->aflags[t];
			dflags = srec->dflags[t];
			if ((t == S) && ((mvBit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)) {
				if (srec->status & S_NEXPIRE)
					aflags |= F_DELETED;
				else
					dflags |= F_DELETED;
			}
			if ((svars->chan->ops[t] & OP_EXPUNGE) && (((srec->msg[t] ? srec->msg[t]->flags : 0) | aflags) & ~dflags & F_DELETED) &&
			    (!svars->ctx[t]->conf->trash || svars->ctx[t]->conf->trash_only_new))
			{
				srec->aflags[t] &= F_DELETED;
				aflags &= F_DELETED;
				srec->dflags[t] = dflags = 0;
			}
			if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS)) {
				aflags &= ~srec->msg[t]->flags;
				dflags &= srec->msg[t]->flags;
			}
			switch ((aflags | dflags) ? svars->drv[t]->set_flags( svars->ctx[t], srec->msg[t], srec->uid[t], aflags, dflags ) : DRV_OK) {
			case DRV_STORE_BAD: svars->ret = SYNC_BAD(t); goto finish;
			case DRV_BOX_BAD: svars->ret = SYNC_FAIL; goto finish;
			default: /* ok */ srec->aflags[t] = srec->dflags[t] = 0; break;
			case DRV_OK:
				if (aflags & F_DELETED)
					srec->status |= S_DEL(t);
				else if (dflags & F_DELETED)
					srec->status &= ~S_DEL(t);
				if (t) {
					nex = (srec->status / S_NEXPIRE) & 1;
					if (nex != ((srec->status / S_EXPIRED) & 1)) {
						if (nex && (svars->smaxxuid < srec->uid[S]))
							svars->smaxxuid = srec->uid[S];
						Fprintf( svars->jfp, "/ %d %d\n", srec->uid[M], srec->uid[S] );
						debug( "  pair(%d,%d): expired %d (commit)\n", srec->uid[M], srec->uid[S], nex );
						srec->status = (srec->status & ~S_EXPIRED) | (nex * S_EXPIRED);
					} else if (nex != ((srec->status / S_EXPIRE) & 1)) {
						Fprintf( svars->jfp, "\\ %d %d\n", srec->uid[M], srec->uid[S] );
						debug( "  pair(%d,%d): expire %d (cancel)\n", srec->uid[M], srec->uid[S], nex );
						srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
					}
				}
			}
		}
		nflags = (srec->flags | srec->aflags[M] | srec->aflags[S]) & ~(srec->dflags[M] | srec->dflags[S]);
		if (srec->flags != nflags) {
			debug( "  pair(%d,%d): updating flags (%u -> %u)\n", srec->uid[M], srec->uid[S], srec->flags, nflags );
			srec->flags = nflags;
			Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], nflags );
		}
	}

	for (t = 0; t < 2; t++) {
		if ((svars->chan->ops[t] & OP_EXPUNGE) &&
			(svars->ctx[t]->conf->trash || (svars->ctx[1-t]->conf->trash && svars->ctx[1-t]->conf->trash_remote_new))) {
			debug( "trashing in %s\n", str_ms[t] );
			for (tmsg = svars->ctx[t]->msgs; tmsg; tmsg = tmsg->next)
				if (tmsg->flags & F_DELETED) {
					if (svars->ctx[t]->conf->trash) {
						if (!svars->ctx[t]->conf->trash_only_new || !tmsg->srec || tmsg->srec->uid[1-t] < 0) {
							debug( "  trashing message %d\n", tmsg->uid );
							switch (svars->drv[t]->trash_msg( svars->ctx[t], tmsg )) {
							case DRV_OK: break;
							case DRV_STORE_BAD: svars->ret = SYNC_BAD(t); goto finish;
							default: svars->ret = SYNC_FAIL; goto nexex;
							}
						} else
							debug( "  not trashing message %d - not new\n", tmsg->uid );
					} else {
						if (!tmsg->srec || tmsg->srec->uid[1-t] < 0) {
							if (!svars->ctx[1-t]->conf->max_size || tmsg->size <= svars->ctx[1-t]->conf->max_size) {
								debug( "  remote trashing message %d\n", tmsg->uid );
								switch ((svars->ret = copy_msg( svars->ctx, 1 - t, tmsg, 0, 0 ))) {
								case SYNC_OK: break;
								case SYNC_NOGOOD: svars->ret = SYNC_FAIL; goto nexex;
								case SYNC_FAIL: goto nexex;
								default: goto finish;
								}
							} else
								debug( "  not remote trashing message %d - too big\n", tmsg->uid );
						} else
							debug( "  not remote trashing message %d - not new\n", tmsg->uid );
					}
				}

			info( "Expunging %s...\n", str_ms[t] );
			debug( "expunging %s\n", str_ms[t] );
			switch (svars->drv[t]->close( svars->ctx[t] )) {
			case DRV_OK: svars->state[t] |= ST_DID_EXPUNGE; break;
			case DRV_STORE_BAD: svars->ret = SYNC_BAD(t); goto finish;
			default: break;
			}
		}
	  nexex: ;
	}
	if ((svars->state[M] | svars->state[S]) & ST_DID_EXPUNGE) {
		/* This cleanup is not strictly necessary, as the next full sync
		   would throw out the dead entries anyway. But ... */

		minwuid = INT_MAX;
		if (svars->smaxxuid) {
			debug( "preparing entry purge - max expired slave uid is %d\n", svars->smaxxuid );
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!((srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) &&
				      (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) || (srec->status & S_EXPIRED))) &&
				    svars->smaxxuid < srec->uid[S] && minwuid > srec->uid[M])
					minwuid = srec->uid[M];
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
		}

		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) {
				if (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) ||
				    ((srec->status & S_EXPIRED) && svars->maxuid[M] >= srec->uid[M] && minwuid > srec->uid[M])) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S] > 0) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (srec->uid[M] > 0 && ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE))) {
				debug( "  -> orphaning ([%d],%d)\n", srec->uid[M], srec->uid[S] );
				Fprintf( svars->jfp, "< %d %d 0\n", srec->uid[M], srec->uid[S] );
				srec->uid[M] = 0;
			}
		}
	}

	Fprintf( svars->nfp, "%d:%d %d:%d:%d\n", svars->uidval[M], svars->maxuid[M], svars->uidval[S], svars->smaxxuid, svars->maxuid[S] );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		Fprintf( svars->nfp, "%d %d %s%s\n", srec->uid[M], srec->uid[S],
		         srec->status & S_EXPIRED ? "X" : "", fbuf );
	}

	Fclose( svars->nfp );
	Fclose( svars->jfp );
	if (!(DFlags & KEEPJOURNAL)) {
		/* order is important! */
		rename( svars->nname, svars->dname );
		unlink( svars->jname );
	}

  bail:
	for (srec = svars->srecs; srec; srec = nsrec) {
		nsrec = srec->next;
		free( srec );
	}
	unlink( svars->lname );
  bail1:
	close( svars->lfd );
  bail2:
	free( svars->lname );
	free( svars->nname );
	free( svars->jname );
	free( svars->dname );
	return svars->ret;

  finish:
	Fclose( svars->nfp );
	Fclose( svars->jfp );
	goto bail;
}

