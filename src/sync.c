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

static const char *str_ms[] = { "master", "slave" }, *str_hl[] = { "push", "pull" };

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
#define S_EXPIRED      (1<<1)
#define S_DEL(ms)      (1<<(2+(ms)))
#define S_EXP_S        (1<<4)
#define S_DONE         (1<<6)

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	int uid[2];
	message_t *msg[2];
	unsigned char flags, status;
} sync_rec_t;

static void
findmsgs( sync_rec_t *srecs, store_t *ctx[], int t )
{
	sync_rec_t *srec, *nsrec = 0;
	message_t *msg;
	const char *diag;
	int uid;
	char fbuf[16]; /* enlarge when support for keywords is added */

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

#define JOURNAL_VERSION "1"

int
sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan )
{
	driver_t *driver[2];
	message_t *tmsg;
	sync_rec_t *recs, *srec, **srecadd, *nsrec, **osrecadd;
	char *dname, *jname, *nname, *lname, *s, *cmname, *csname;
	FILE *dfp, *jfp, *nfp;
	int opts[2];
	int nom, nos, del[2], ex[2];
	int muidval, suidval, smaxxuid, maxuid[2], minwuid, maxwuid;
	int t1, t2, t3, t, uid, nmsgs;
	int lfd, ret, line, sline, todel, delt, *mexcs, nmexcs, rmexcs;
	unsigned char nflags;
	msg_data_t msgdata;
	struct stat st;
	struct flock lck;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[64];

	ret = SYNC_OK;
	recs = 0, srecadd = &recs;

	for (t = 0; t < 2; t++) {
		ctx[t]->name =
			(!names[t] || (ctx[t]->conf->map_inbox && !strcmp( ctx[t]->conf->map_inbox, names[t] ))) ?
				"INBOX" : names[t];
		ctx[t]->uidvalidity = 0;
		driver[t] = ctx[t]->conf->driver;
		driver[t]->prepare_paths( ctx[t] );
	}

	if (!strcmp( chan->sync_state ? chan->sync_state : global_sync_state, "*" )) {
		if (!ctx[S]->path) {
			fprintf( stderr, "Error: store '%s' does not support in-box sync state\n", chan->stores[S]->name );
			return SYNC_BAD(S);
		}
		nfasprintf( &dname, "%s/." EXE "state", ctx[S]->path );
	} else {
		csname = clean_strdup( ctx[S]->name );
		if (chan->sync_state)
			nfasprintf( &dname, "%s%s", chan->sync_state, csname );
		else {
			cmname = clean_strdup( ctx[M]->name );
			nfasprintf( &dname, "%s:%s:%s_:%s:%s", global_sync_state,
			            chan->stores[M]->name, cmname, chan->stores[S]->name, csname );
			free( cmname );
		}
		free( csname );
	}
	nfasprintf( &jname, "%s.journal", dname );
	nfasprintf( &nname, "%s.new", dname );
	nfasprintf( &lname, "%s.lock", dname );
	muidval = suidval = smaxxuid = maxuid[M] = maxuid[S] = 0;
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	line = 0;
	if ((lfd = open( lname, O_WRONLY|O_CREAT, 0666 )) < 0) {
		if (errno != ENOENT) {
		  lferr:
			fprintf( stderr, "Error: cannot create lock file %s: %s\n", lname, strerror(errno) );
			ret = SYNC_FAIL;
			goto bail2;
		}
		goto skiprd;
	}
	if (fcntl( lfd, F_SETLK, &lck )) {
	  lckerr:
		fprintf( stderr, "Error: channel :%s:%s-:%s:%s is locked\n",
		         chan->stores[M]->name, ctx[M]->name, chan->stores[S]->name, ctx[S]->name );
		ret = SYNC_FAIL;
		goto bail1;
	}
	if ((dfp = fopen( dname, "r" ))) {
		debug( "reading sync state %s ...\n", dname );
		if (!fgets( buf, sizeof(buf), dfp ) || !(t = strlen( buf )) || buf[t - 1] != '\n') {
			fprintf( stderr, "Error: incomplete sync state header in %s\n", dname );
			fclose( dfp );
			ret = SYNC_FAIL;
			goto bail;
		}
		if (sscanf( buf, "%d:%d %d:%d:%d", &muidval, &maxuid[M], &suidval, &smaxxuid, &maxuid[S]) != 5) {
			fprintf( stderr, "Error: invalid sync state header in %s\n", dname );
			fclose( dfp );
			ret = SYNC_FAIL;
			goto bail;
		}
		sline = 1;
		while (fgets( buf, sizeof(buf), dfp )) {
			sline++;
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				fprintf( stderr, "Error: incomplete sync state entry at %s:%d\n", dname, sline );
				fclose( dfp );
				ret = SYNC_FAIL;
				goto bail;
			}
			fbuf[0] = 0;
			if (sscanf( buf, "%d %d %15s", &t1, &t2, fbuf ) < 2) {
				fprintf( stderr, "Error: invalid sync state entry at %s:%d\n", dname, sline );
				fclose( dfp );
				ret = SYNC_FAIL;
				goto bail;
			}
			srec = nfmalloc( sizeof(*srec) );
			srec->uid[M] = t1;
			srec->uid[S] = t2;
			s = fbuf;
			if (*s == 'X') {
				s++;
				srec->status = S_EXPIRED;
			} else
				srec->status = 0;
			srec->flags = parse_flags( s );
			debug( "  entry (%d,%d,%u,%s)\n", srec->uid[M], srec->uid[S], srec->flags, srec->status & S_EXPIRED ? "X" : "" );
			srec->msg[M] = srec->msg[S] = 0;
			srec->next = 0;
			*srecadd = srec;
			srecadd = &srec->next;
		}
		fclose( dfp );
	} else {
		if (errno != ENOENT) {
			fprintf( stderr, "Error: cannot read sync state %s\n", dname );
			ret = SYNC_FAIL;
			goto bail;
		}
	}
	if ((jfp = fopen( jname, "r" ))) {
		if (!stat( nname, &st ) && fgets( buf, sizeof(buf), jfp )) {
			debug( "recovering journal ...\n" );
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				fprintf( stderr, "Error: incomplete journal header in %s\n", jname );
				fclose( jfp );
				ret = SYNC_FAIL;
				goto bail;
			}
			if (memcmp( buf, JOURNAL_VERSION "\n", strlen(JOURNAL_VERSION) + 1 )) {
				fprintf( stderr, "Error: incompatible journal version "
				                 "(got %.*s, expected " JOURNAL_VERSION ")\n", t - 1, buf );
				fclose( jfp );
				ret = SYNC_FAIL;
				goto bail;
			}
			srec = 0;
			line = 1;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
					fprintf( stderr, "Error: incomplete journal entry at %s:%d\n", jname, line );
					fclose( jfp );
					ret = SYNC_FAIL;
					goto bail;
				}
				if (buf[0] == '(' || buf[0] == ')' ?
				        (sscanf( buf + 2, "%d", &t1 ) != 1) :
				    buf[0] == '-' || buf[0] == '|' ?
					(sscanf( buf + 2, "%d %d", &t1, &t2 ) != 2) :
					(sscanf( buf + 2, "%d %d %d", &t1, &t2, &t3 ) != 3))
				{
					fprintf( stderr, "Error: malformed journal entry at %s:%d\n", jname, line );
					fclose( jfp );
					ret = SYNC_FAIL;
					goto bail;
				}
				if (buf[0] == '(')
					maxuid[M] = t1;
				else if (buf[0] == ')')
					maxuid[S] = t1;
				else if (buf[0] == '|') {
					muidval = t1;
					suidval = t2;
				} else if (buf[0] == '+') {
					srec = nfmalloc( sizeof(*srec) );
					srec->uid[M] = t1;
					srec->uid[S] = t2;
					srec->flags = t3;
					debug( "  new entry(%d,%d,%u)\n", t1, t2, t3 );
					srec->msg[M] = srec->msg[S] = 0;
					srec->status = 0;
					srec->next = 0;
					*srecadd = srec;
					srecadd = &srec->next;
				} else {
					for (nsrec = srec; srec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					for (srec = recs; srec != nsrec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					fprintf( stderr, "Error: journal entry at %s:%d refers to non-existing sync state entry\n", jname, line );
					fclose( jfp );
					ret = SYNC_FAIL;
					goto bail;
				  syncfnd:
					debug( "  entry(%d,%d,%u) ", srec->uid[M], srec->uid[S], srec->flags );
					switch (buf[0]) {
					case '-':
						debug( "killed\n" );
						srec->status = S_DEAD;
						break;
					case '<':
						debug( "master now %d\n", t3 );
						srec->uid[M] = t3;
						break;
					case '>':
						debug( "slave now %d\n", t3 );
						srec->uid[S] = t3;
						break;
					case '*':
						debug( "flags now %d\n", t3 );
						srec->flags = t3;
						break;
					case '~':
						debug( "expired now %d\n", t3 );
						if (t3) {
							if (smaxxuid < t2)
								smaxxuid = t2;
							srec->status |= S_EXPIRED;
						} else
							srec->status &= ~S_EXPIRED;
						break;
					default:
						fprintf( stderr, "Error: unrecognized journal entry at %s:%d\n", jname, line );
						fclose( jfp );
						ret = SYNC_FAIL;
						goto bail;
					}
				}
			}
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			fprintf( stderr, "Error: cannot read journal %s\n", jname );
			ret = SYNC_FAIL;
			goto bail;
		}
	}
  skiprd:

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
	driver[M]->prepare_opts( ctx[M], opts[M] );
	driver[S]->prepare_opts( ctx[S], opts[S] );

	if (ctx[S]->opts & OPEN_NEW)
		maxwuid = INT_MAX;
	else if (ctx[S]->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = recs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->uid[S] > maxwuid)
				maxwuid = srec->uid[S];
	} else
		maxwuid = 0;
	info( "Selecting slave %s... ", ctx[S]->name );
	debug( maxwuid == INT_MAX ? "selecting slave [1,inf]\n" : "selecting slave [1,%d]\n", maxwuid );
	switch (driver[S]->select( ctx[S], (ctx[S]->opts & OPEN_OLD) ? 1 : maxuid[S] + 1, maxwuid, 0, 0 )) {
	case DRV_STORE_BAD: ret = SYNC_BAD(S); goto bail;
	case DRV_BOX_BAD: ret = SYNC_FAIL; goto bail;
	}
	info( "%d messages, %d recent\n", ctx[S]->count, ctx[S]->recent );
	findmsgs( recs, ctx, S );

	if (suidval && suidval != ctx[S]->uidvalidity) {
		fprintf( stderr, "Error: UIDVALIDITY of slave changed\n" );
		ret = SYNC_FAIL;
		goto bail;
	}

	s = strrchr( dname, '/' );
	*s = 0;
	mkdir( dname, 0700 );
	*s = '/';
	if (lfd < 0) {
		if ((lfd = open( lname, O_WRONLY|O_CREAT, 0666 )) < 0)
			goto lferr;
		if (fcntl( lfd, F_SETLK, &lck ))
			goto lckerr;
	}
	if (!(nfp = fopen( nname, "w" ))) {
		fprintf( stderr, "Error: cannot write new sync state %s\n", nname );
		ret = SYNC_FAIL;
		goto bail;
	}
	if (!(jfp = fopen( jname, "a" ))) {
		fprintf( stderr, "Error: cannot write journal %s\n", jname );
		fclose( nfp );
		ret = SYNC_FAIL;
		goto bail;
	}
	setlinebuf( jfp );
	if (!line)
		Fprintf( jfp, JOURNAL_VERSION "\n" );

	mexcs = 0;
	nmexcs = rmexcs = 0;
	minwuid = INT_MAX;
	if (smaxxuid) {
		debug( "preparing master selection - max expired slave uid is %d\n", smaxxuid );
		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXPIRED) {
				if (!srec->uid[S] || ((ctx[S]->opts & OPEN_OLD) && !srec->msg[S])) {
					srec->status |= S_EXP_S;
					continue;
				}
			} else {
				if (smaxxuid >= srec->uid[S])
					continue;
			}
			if (minwuid > srec->uid[M])
				minwuid = srec->uid[M];
		}
		debug( "  min non-orphaned master uid is %d\n", minwuid );
		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXP_S) {
				if (minwuid > srec->uid[M] && maxuid[M] >= srec->uid[M]) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S]) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (minwuid > srec->uid[M]) {
				if (srec->uid[S] < 0) {
					if (maxuid[M] >= srec->uid[M]) {
						debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
						srec->status = S_DEAD;
						Fprintf( jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
					}
				} else if (srec->uid[M] > 0 && srec->uid[S] && (ctx[M]->opts & OPEN_OLD) &&
				           (!(ctx[M]->opts & OPEN_NEW) || maxuid[M] >= srec->uid[M])) {
					if (nmexcs == rmexcs) {
						rmexcs = rmexcs * 2 + 100;
						mexcs = nfrealloc( mexcs, rmexcs * sizeof(int) );
					}
					mexcs[nmexcs++] = srec->uid[M];
				}
			}
		}
		debug( "  exception list is:" );
		for (t = 0; t < nmexcs; t++)
			debug( " %d", mexcs[t] );
		debug( "\n" );
	} else if (ctx[M]->opts & OPEN_OLD)
		minwuid = 1;
	if (ctx[M]->opts & OPEN_NEW) {
		if (minwuid > maxuid[M] + 1)
			minwuid = maxuid[M] + 1;
		maxwuid = INT_MAX;
	} else if (ctx[M]->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = recs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->uid[M] > maxwuid)
				maxwuid = srec->uid[M];
	} else
		maxwuid = 0;
	info( "Selecting master %s... ", ctx[M]->name );
	debug( maxwuid == INT_MAX ? "selecting master [%d,inf]\n" : "selecting master [%d,%d]\n", minwuid, maxwuid );
	switch (driver[M]->select( ctx[M], minwuid, maxwuid, mexcs, nmexcs )) {
	case DRV_STORE_BAD: ret = SYNC_BAD(M); goto finish;
	case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
	}
	info( "%d messages, %d recent\n", ctx[M]->count, ctx[M]->recent );
	findmsgs( recs, ctx, M );

	if (muidval && muidval != ctx[M]->uidvalidity) {
		fprintf( stderr, "Error: UIDVALIDITY of master changed\n" );
		ret = SYNC_FAIL;
		goto finish;
	}

	if (!muidval || !suidval) {
		muidval = ctx[M]->uidvalidity;
		suidval = ctx[S]->uidvalidity;
		Fprintf( jfp, "| %d %d\n", muidval, suidval );
	}

	info( "Synchronizing...\n" );

	debug( "synchronizing new entries\n" );
	osrecadd = srecadd;
	for (t = 0; t < 2; t++) {
		for (nmsgs = 0, tmsg = ctx[1-t]->msgs; tmsg; tmsg = tmsg->next)
			if (tmsg->srec ? tmsg->srec->uid[t] < 0 && (chan->ops[t] & OP_RENEW) : (chan->ops[t] & OP_NEW)) {
				debug( "new message %d on %s\n", tmsg->uid, str_ms[1-t] );
				if ((chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED))
					debug( "  not %sing - would be expunged anyway\n", str_hl[t] );
				else {
					if ((tmsg->flags & F_FLAGGED) || !chan->stores[t]->max_size || tmsg->size <= chan->stores[t]->max_size) {
						debug( "  %sing it\n", str_hl[t] );
						if (!nmsgs)
							info( t ? "Pulling new messages..." : "Pushing new messages..." );
						else
							infoc( '.' );
						nmsgs++;
						msgdata.flags = tmsg->flags;
						switch (driver[1-t]->fetch_msg( ctx[1-t], tmsg, &msgdata )) {
						case DRV_STORE_BAD: return SYNC_BAD(1-t);
						case DRV_BOX_BAD: return SYNC_FAIL;
						case DRV_MSG_BAD: /* ok */ continue;
						}
						tmsg->flags = msgdata.flags;
						switch (driver[t]->store_msg( ctx[t], &msgdata, &uid )) {
						case DRV_STORE_BAD: return SYNC_BAD(t);
						default: return SYNC_FAIL;
						case DRV_OK: break;
						}
					} else {
						if (tmsg->srec) {
							debug( "  -> not %sing - still too big\n", str_hl[t] );
							continue;
						}
						debug( "  not %sing - too big\n", str_hl[t] );
						uid = -1;
					}
					if (tmsg->srec) {
						srec = tmsg->srec;
						Fprintf( jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
					} else {
						srec = nfmalloc( sizeof(*srec) );
						srec->next = 0;
						*srecadd = srec;
						srecadd = &srec->next;
						srec->uid[1-t] = tmsg->uid;
					}
					srec->uid[t] = uid;
					srec->flags = tmsg->flags;
					srec->status = S_DONE;
					if (tmsg->srec)
						Fprintf( jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], srec->flags );
					else {
						tmsg->srec = srec;
						if (maxuid[1-t] < tmsg->uid) {
							maxuid[1-t] = tmsg->uid;
							Fprintf( jfp, "%c %d\n", ")("[t], tmsg->uid );
						}
						Fprintf( jfp, "+ %d %d %u\n", srec->uid[M], srec->uid[S], srec->flags );
					}
				}
			}
		if (nmsgs)
			info( " %d messages\n", nmsgs );
	}

	debug( "synchronizing old entries\n" );
	for (srec = recs; srec != *osrecadd; srec = srec->next) {
		if (srec->status & (S_DEAD|S_DONE))
			continue;
		debug( "pair (%d,%d)\n", srec->uid[M], srec->uid[S] );
		nom = !srec->msg[M] && (ctx[M]->opts & OPEN_OLD);
		nos = !srec->msg[S] && (ctx[S]->opts & OPEN_OLD);
		if (nom && nos) {
			debug( "  vanished\n" );
			/* d.1) d.5) d.6) d.10) d.11) */
			srec->status = S_DEAD;
			Fprintf( jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
		} else {
			del[M] = nom && (srec->uid[M] > 0);
			del[S] = nos && (srec->uid[S] > 0);
			if (srec->msg[M] && (srec->msg[M]->flags & F_DELETED))
				srec->status |= S_DEL(M);
			if (srec->msg[S] && (srec->msg[S]->flags & F_DELETED))
				srec->status |= S_DEL(S);
			nflags = srec->flags;

			for (t = 0; t < 2; t++) {
				int unex;
				unsigned char sflags, aflags, dflags;

				/* excludes (push) c.3) d.2) d.3) d.4) / (pull) b.3) d.7) d.8) d.9) */
				if (!srec->uid[t]) {
					/* b.1) / c.1) */
					debug( "  no more %s\n", str_ms[t] );
				} else if (del[1-t]) {
					/* c.4) d.9) / b.4) d.4) */
					if (srec->msg[t] && srec->msg[t]->flags != nflags)
						info( "Info: conflicting changes in (%d,%d)\n", srec->uid[M], srec->uid[S] );
					if (chan->ops[t] & OP_DELETE) {
						debug( "  %sing delete\n", str_hl[t] );
						switch (driver[t]->set_flags( ctx[t], srec->msg[t], srec->uid[t], F_DELETED, 0 )) {
						case DRV_STORE_BAD: ret = SYNC_BAD(t); goto finish;
						case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
						default: /* ok */ break;
						case DRV_OK:
							srec->status |= S_DEL(t);
							Fprintf( jfp, "%c %d %d 0\n", "><"[t], srec->uid[M], srec->uid[S] );
							srec->uid[1-t] = 0;
						}
					} else
						debug( "  not %sing delete\n", str_hl[t] );
				} else if (!srec->msg[1-t])
					/* c.1) c.2) d.7) d.8) / b.1) b.2) d.2) d.3) */
					;
				else if (srec->uid[t] < 0)
					/* b.2) / c.2) */
					; /* handled above */
				else if (!del[t]) {
					/* a) & b.3) / c.3) */
					if (chan->ops[t] & OP_FLAGS) {
						sflags = srec->msg[1-t]->flags;
						aflags = sflags & ~nflags;
						dflags = ~sflags & nflags;
						unex = 0;
						if (srec->status & S_EXPIRED) {
							if (!t) {
								if ((aflags & ~F_DELETED) || dflags)
									info( "Info: Flags of expired message changed in (%d,%d)\n", srec->uid[M], srec->uid[S] );
								continue;
							} else {
								if ((sflags & F_FLAGGED) && !(sflags & F_DELETED)) {
									unex = 1;
									dflags |= F_DELETED;
								} else
									continue;
							}
						}
						if ((chan->ops[t] & OP_EXPUNGE) && (sflags & F_DELETED) &&
						    (!ctx[t]->conf->trash || ctx[t]->conf->trash_only_new))
						{
							aflags &= F_DELETED;
							dflags = 0;
						}
						if (DFlags & DEBUG) {
							char afbuf[16], dfbuf[16]; /* enlarge when support for keywords is added */
							make_flags( aflags, afbuf );
							make_flags( dflags, dfbuf );
							debug( "  %sing flags: +%s -%s\n", str_hl[t], afbuf, dfbuf );
						}
						switch ((aflags | dflags) ? driver[t]->set_flags( ctx[t], srec->msg[t], srec->uid[t], aflags, dflags ) : DRV_OK) {
						case DRV_STORE_BAD: ret = SYNC_BAD(t); goto finish;
						case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
						default: /* ok */ break;
						case DRV_OK:
							if (aflags & F_DELETED)
								srec->status |= S_DEL(t);
							else if (dflags & F_DELETED)
								srec->status &= ~S_DEL(t);
							nflags = (nflags | aflags) & ~dflags;
							if (unex) {
								debug( "unexpiring pair(%d,%d)\n", srec->uid[M], srec->uid[S] );
								/* log last, so deletion can't be misinterpreted! */
								Fprintf( jfp, "~ %d %d 0\n", srec->uid[M], srec->uid[S] );
								srec->status &= ~S_EXPIRED;
							}
						}
					} else
						debug( "  not %sing flags\n", str_hl[t] );
				} /* else b.4) / c.4) */
			}

			if (srec->flags != nflags) {
				debug( "  updating flags (%u -> %u)\n", srec->flags, nflags );
				srec->flags = nflags;
				Fprintf( jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], nflags );
			}
		}
	}

	if ((chan->ops[S] & (OP_NEW|OP_RENEW)) && chan->max_messages) {
		debug( "expiring excess entries\n" );
		todel = ctx[S]->count - chan->max_messages;
		for (tmsg = ctx[S]->msgs; tmsg && todel > 0; tmsg = tmsg->next)
			if (!(tmsg->status & M_DEAD) && (tmsg->flags & F_DELETED))
				todel--;
		delt = 0;
		for (tmsg = ctx[S]->msgs; tmsg && todel > 0; tmsg = tmsg->next) {
			if ((tmsg->status & M_DEAD) || (tmsg->flags & F_DELETED))
				continue;
			if ((tmsg->flags & F_FLAGGED) || !tmsg->srec || tmsg->srec->uid[M] <= 0) /* add M_DESYNCED? */
				todel--;
			else if (!(tmsg->status & M_RECENT)) {
				tmsg->status |= M_EXPIRE;
				delt++;
				todel--;
			}
		}
		if (delt) {
			for (srec = recs; srec; srec = srec->next) {
				if (srec->status & (S_DEAD|S_EXPIRED))
					continue;
				if (srec->msg[S] && (srec->msg[S]->status & M_EXPIRE)) {
					debug( "  expiring pair(%d,%d)\n", srec->uid[M], srec->uid[S] );
					/* log first, so deletion can't be misinterpreted! */
					Fprintf( jfp, "~ %d %d 1\n", srec->uid[M], srec->uid[S] );
					if (smaxxuid < srec->uid[S])
						smaxxuid = srec->uid[S];
					srec->status |= S_EXPIRED;
					switch (driver[S]->set_flags( ctx[S], srec->msg[S], 0, F_DELETED, 0 )) {
					case DRV_STORE_BAD: ret = SYNC_BAD(S); goto finish;
					case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
					default: /* ok */ break;
					case DRV_OK: srec->status |= S_DEL(S);
					}
				}
			}
		}
	}

	for (t = 0; t < 2; t++) {
		ex[t] = 0;
		if (chan->ops[t] & OP_EXPUNGE) {
			info( "Expunging %s\n", str_ms[t] );
			debug( "expunging %s\n", str_ms[t] );
			for (tmsg = ctx[t]->msgs; tmsg; tmsg = tmsg->next)
				if (tmsg->flags & F_DELETED) {
					if (ctx[t]->conf->trash) {
						if (!ctx[t]->conf->trash_only_new || !tmsg->srec || tmsg->srec->uid[1-t] < 0) {
							debug( "  trashing message %d\n", tmsg->uid );
							switch (driver[t]->trash_msg( ctx[t], tmsg )) {
							case DRV_OK: break;
							case DRV_STORE_BAD: ret = SYNC_BAD(t); goto finish;
							default: ret = SYNC_FAIL; goto nexex;
							}
						} else
							debug( "  not trashing message %d - not new\n", tmsg->uid );
					} else if (ctx[1-t]->conf->trash && ctx[1-t]->conf->trash_remote_new) {
						if (!tmsg->srec || tmsg->srec->uid[1-t] < 0) {
							if (!ctx[1-t]->conf->max_size || tmsg->size <= ctx[1-t]->conf->max_size) {
								debug( "  remote trashing message %d\n", tmsg->uid );
								msgdata.flags = tmsg->flags;
								switch (driver[t]->fetch_msg( ctx[t], tmsg, &msgdata )) {
								case DRV_OK: break;
								case DRV_STORE_BAD: ret = SYNC_BAD(t); goto finish;
								default: ret = SYNC_FAIL; goto nexex;
								}
								switch (driver[1-t]->store_msg( ctx[1-t], &msgdata, 0 )) {
								case DRV_OK: break;
								case DRV_STORE_BAD: ret = SYNC_BAD(1-t); goto finish;
								default: ret = SYNC_FAIL; goto nexex;
								}
							} else
								debug( "  not remote trashing message %d - too big\n", tmsg->uid );
						} else
							debug( "  not remote trashing message %d - not new\n", tmsg->uid );
					}
				}

			switch (driver[t]->close( ctx[t] )) {
			case DRV_OK: ex[t] = 1; break;
			case DRV_STORE_BAD: ret = SYNC_BAD(t); goto finish;
			default: break;
			}
		}
	  nexex: ;
	}
	if (ex[M] || ex[S]) {
		/* This cleanup is not strictly necessary, as the next full sync
		   would throw out the dead entries anyway. But ... */

		minwuid = INT_MAX;
		if (smaxxuid) {
			debug( "preparing entry purge - max expired slave uid is %d\n", smaxxuid );
			for (srec = recs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!((srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && ex[S])) &&
				      (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && ex[M]) || (srec->status & S_EXPIRED))) &&
				    smaxxuid < srec->uid[S] && minwuid > srec->uid[M])
					minwuid = srec->uid[M];
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
		}

		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && ex[S])) {
				if (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && ex[M]) ||
				    ((srec->status & S_EXPIRED) && maxuid[M] >= srec->uid[M] && minwuid > srec->uid[M])) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S] > 0) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (srec->uid[M] > 0 && ((srec->status & S_DEL(M)) && ex[M])) {
				debug( "  -> orphaning ([%d],%d)\n", srec->uid[M], srec->uid[S] );
				Fprintf( jfp, "< %d %d 0\n", srec->uid[M], srec->uid[S] );
				srec->uid[M] = 0;
			}
		}
	}

  finish:
	Fprintf( nfp, "%d:%d %d:%d:%d\n", muidval, maxuid[M], suidval, smaxxuid, maxuid[S] );
	for (srec = recs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		Fprintf( nfp, "%d %d %s%s\n", srec->uid[M], srec->uid[S],
		         srec->status & S_EXPIRED ? "X" : "", fbuf );
	}

	fclose( nfp );
	fclose( jfp );
	if (!(DFlags & KEEPJOURNAL)) {
		/* order is important! */
		rename( nname, dname );
		unlink( jname );
	}

  bail:
	for (srec = recs; srec; srec = nsrec) {
		nsrec = srec->next;
		free( srec );
	}
	unlink( lname );
  bail1:
	close( lfd );
  bail2:
	free( lname );
	free( nname );
	free( jname );
	free( dname );
	return ret;
}

