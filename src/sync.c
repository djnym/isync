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

static void
makeopts( int dops, store_conf_t *dconf, int *dopts,
          store_conf_t *sconf, int *sopts )
{
	if (dops & (OP_DELETE|OP_FLAGS)) {
		*dopts |= OPEN_SETFLAGS;
		*sopts |= OPEN_OLD;
		if (dops & OP_FLAGS)
			*sopts |= OPEN_FLAGS;
	}
	if (dops & (OP_NEW|OP_RENEW)) {
		*dopts |= OPEN_APPEND;
		if (dops & OP_RENEW)
			*sopts |= OPEN_OLD;
		if (dops & OP_NEW)
			*sopts |= OPEN_NEW;
		if (dops & OP_EXPUNGE)
			*sopts |= OPEN_FLAGS;
		if (dconf->max_size)
			*sopts |= OPEN_SIZE;
	}
	if (dops & OP_EXPUNGE) {
		*dopts |= OPEN_EXPUNGE;
		if (dconf->trash) {
			if (!dconf->trash_only_new)
				*dopts |= OPEN_OLD;
			*dopts |= OPEN_NEW|OPEN_FLAGS;
		} else if (sconf->trash && sconf->trash_remote_new)
			*dopts |= OPEN_NEW|OPEN_FLAGS;
	}
	if (dops & OP_CREATE)
		*dopts |= OPEN_CREATE;
}

static void
dump_box( store_t *ctx )
{
	message_t *msg;
	char fbuf[16]; /* enlarge when support for keywords is added */

	if (Debug)
		for (msg = ctx->msgs; msg; msg = msg->next) {
			make_flags( msg->flags, fbuf );
			printf( "  message %d, %s, %d\n", msg->uid, fbuf, msg->size );
		}
}

static message_t *
findmsg( store_t *ctx, int uid, message_t **nmsg, const char *who )
{
	message_t *msg;

	if (uid > 0) {
		if (*nmsg && (*nmsg)->uid == uid) {
			debug( " %s came in sequence\n", who );
			msg = *nmsg;
		  found:
			*nmsg = msg->next;
			if (!(msg->status & M_DEAD)) {
				msg->status |= M_PROCESSED;
				return msg;
			}
			debug( "  ... but it vanished under our feet!\n" );
		} else {
			for (msg = ctx->msgs; msg; msg = msg->next)
				if (msg->uid == uid) {
					debug( " %s came out of sequence\n", who );
					goto found;
				}
				debug( " %s not present\n", who );
		}
	} else
		debug( " no %s expected\n", who );
	return 0;
}

#define S_DEAD         (1<<0)
#define S_EXPIRED      (1<<1)
#define S_DEL_MASTER   (1<<2)
#define S_DEL_SLAVE    (1<<3)
#define S_EXP_SLAVE    (1<<4)

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	int muid, suid;
	unsigned char flags, status;
} sync_rec_t;


#define EX_OK           0
#define EX_FAIL         1
#define EX_STORE_BAD    2
#define EX_RSTORE_BAD   3

static int
expunge( store_t *ctx, store_t *rctx )
{
	driver_t *driver = ctx->conf->driver, *rdriver = rctx->conf->driver;
	message_t *msg;
	msg_data_t msgdata;

	for (msg = ctx->msgs; msg; msg = msg->next)
		if (msg->flags & F_DELETED) {
			if (ctx->conf->trash) {
				if (!ctx->conf->trash_only_new || (msg->status & M_NOT_SYNCED)) {
					debug( "  trashing message %d\n", msg->uid );
					switch (driver->trash_msg( ctx, msg )) {
					case DRV_STORE_BAD: return EX_STORE_BAD;
					default: return EX_FAIL;
					case DRV_OK: break;
					}
				} else
					debug( "  not trashing message %d - not new\n", msg->uid );
			} else if (rctx->conf->trash && rctx->conf->trash_remote_new) {
				if (msg->status & M_NOT_SYNCED) {
					if (!rctx->conf->max_size || msg->size <= rctx->conf->max_size) {
						debug( "  remote trashing message %d\n", msg->uid );
						msgdata.flags = msg->flags;
						switch (driver->fetch_msg( ctx, msg, &msgdata )) {
						case DRV_STORE_BAD: return EX_STORE_BAD;
						default: return EX_FAIL;
						case DRV_OK: break;
						}
						switch (rdriver->store_msg( rctx, &msgdata, 0 )) {
						case DRV_STORE_BAD: return EX_RSTORE_BAD;
						default: return EX_FAIL;
						case DRV_OK: break;
						}
					} else
						debug( "  not remote trashing message %d - too big\n", msg->uid );
				} else
					debug( "  not remote trashing message %d - not new\n", msg->uid );
			}
		}

	switch (driver->close( ctx )) {
	case DRV_STORE_BAD: return EX_STORE_BAD;
	default: return EX_FAIL;
	case DRV_OK: return EX_OK;;
	}
}

/* cases:
   a) both non-null
   b) only master null
   b.1) muid 0
   b.2) muid -1
   b.3) master not scanned
   b.4) master gone
   c) only slave null
   c.1) suid 0
   c.2) suid -1
   c.3) slave not scanned
   c.4) slave gone
   d) both null
   d.1) both gone
   d.2) muid 0, slave not scanned
   d.3) muid -1, slave not scanned
   d.4) master gone, slave not scanned
   d.5) muid 0, slave gone
   d.6) muid -1, slave gone
   d.7) suid 0, master not scanned
   d.8) suid -1, master not scanned
   d.9) slave gone, master not scanned
   d.10) suid 0, master gone
   d.11) suid -1, master gone
   impossible cases: both muid & suid 0 or -1, both not scanned
*/
static int
sync_old( int tops, store_t *sctx, store_t *tctx, store_conf_t *tconf, FILE *jfp, int pull,
          unsigned char *nflags, sync_rec_t *srec, message_t *smsg, message_t *tmsg, int dels, int delt )
{
	driver_t *tdriver = tctx->conf->driver, *sdriver = sctx->conf->driver;
	int uid, tuid, unex;
	unsigned char sflags, aflags, dflags, rflags;
	msg_data_t msgdata;

	/* excludes (push) c.3) d.2) d.3) d.4) / (pull) b.3) d.7) d.8) d.9) */
	tuid = pull ? srec->suid : srec->muid;
	if (!tuid) {
		/* b.1) / c.1) */
		debug( pull ? "  no more slave\n" : "  no more master\n" );
	} else if (dels) {
		/* c.4) d.9) / b.4) d.4) */
		debug( pull ? "  master vanished\n" : "  slave vanished\n" );
		if (tmsg && tmsg->flags != *nflags)
			info( "Info: conflicting changes in (%d,%d)\n", srec->muid, srec->suid );
		if (tops & OP_DELETE) {
			debug( pull ? "  -> pulling delete\n" : "  -> pushing delete\n" );
			switch (tdriver->set_flags( tctx, tmsg, tuid, F_DELETED, 0 )) {
			case DRV_STORE_BAD: return pull ? SYNC_SLAVE_BAD : SYNC_MASTER_BAD;
			case DRV_BOX_BAD: return SYNC_FAIL;
			default: /* ok */ break;
			case DRV_OK:
				if (pull) {
					fprintf( jfp, "< %d %d 0\n", srec->muid, srec->suid );
					srec->muid = 0;
				} else {
					fprintf( jfp, "> %d %d 0\n", srec->muid, srec->suid );
					srec->suid = 0;
				}
			}
		}
	} else if (!smsg)
		/* c.1) c.2) d.7) d.8) / b.1) b.2) d.2) d.3) */
		;
	else if (tuid < 0) {
		/* b.2) / c.2) */
		debug( pull ? "  no slave yet\n" : "  no master yet\n" );
		if (tops & OP_RENEW) {
			if ((tops & OP_EXPUNGE) && (smsg->flags & F_DELETED)) {
				debug( pull ? "  -> not pulling - would be expunged anyway\n" : "  -> not pushing - would be expunged anyway\n" );
				smsg->status |= M_NOT_SYNCED;
			} else {
				if ((smsg->flags & F_FLAGGED) || !tconf->max_size || smsg->size <= tconf->max_size) {
					debug( pull ? "  -> pulling it\n" : "  -> pushing it\n" );
					msgdata.flags = smsg->flags;
					switch (sdriver->fetch_msg( sctx, smsg, &msgdata )) {
					case DRV_STORE_BAD: return pull ? SYNC_MASTER_BAD : SYNC_SLAVE_BAD;
					case DRV_BOX_BAD: return SYNC_FAIL;
					default: /* ok */ smsg->status |= M_NOT_SYNCED; break;
					case DRV_OK:
						smsg->flags = msgdata.flags;
						switch (tdriver->store_msg( tctx, &msgdata, &uid )) {
						case DRV_STORE_BAD: return pull ? SYNC_SLAVE_BAD : SYNC_MASTER_BAD;
						default: return SYNC_FAIL;
						case DRV_OK:
							if (pull) {
								srec->suid = uid;
								fprintf( jfp, "> %d -1 %d\n", srec->muid, srec->suid );
							} else {
								srec->muid = uid;
								fprintf( jfp, "< -1 %d %d\n", srec->suid, srec->muid );
							}
							*nflags = smsg->flags;
						}
					}
				} else {
					debug( pull ? "  -> not pulling - still too big\n" : "  -> not pushing - still too big\n" );
					smsg->status |= M_NOT_SYNCED;
				}
			}
		} else
			smsg->status |= M_NOT_SYNCED;
	} else if (!delt) {
		/* a) & b.3) / c.3) */
		debug( pull ? "  may pull\n" : "  may push\n" );
		if (tops & OP_FLAGS) {
			debug( pull ? "  -> pulling flags\n" : "  -> pushing flags\n" );
			sflags = smsg->flags;
			aflags = sflags & ~*nflags;
			dflags = ~sflags & *nflags;
			unex = 0;
			if (srec->status & S_EXPIRED) {
				if (!pull) {
					if (sflags & F_DELETED) {
						if (!(sflags & F_FLAGGED))
							aflags &= ~F_DELETED;
					} else
						unex = 1;
				} else {
					if ((sflags & F_FLAGGED) && !(sflags & F_DELETED)) {
						unex = 1;
						dflags |= F_DELETED;
					}
				}
			}
			rflags = (*nflags | aflags) & ~dflags;
			if ((tops & OP_EXPUNGE) && (rflags & F_DELETED) &&
			    (!tctx->conf->trash || tctx->conf->trash_only_new))
			{
				aflags &= F_DELETED;
				dflags = 0;
			}
			switch (tdriver->set_flags( tctx, tmsg, tuid, aflags, dflags )) {
			case DRV_STORE_BAD: return pull ? SYNC_SLAVE_BAD : SYNC_MASTER_BAD;
			case DRV_BOX_BAD: return SYNC_FAIL;
			default: /* ok */ break;
			case DRV_OK:
				*nflags = rflags;
				if (unex) {
					debug( "unexpiring pair(%d,%d)\n", srec->muid, srec->suid );
					/* log last, so deletion can't be misinterpreted! */
					fprintf( jfp, "~ %d %d 0\n", srec->muid, srec->suid );
					srec->status &= ~S_EXPIRED;
				}
			}
		}
	} /* else b.4) / c.4) */
	return SYNC_OK;
}

static int
sync_new( int tops, store_t *sctx, store_t *tctx, store_conf_t *tconf, FILE *jfp, sync_rec_t ***srecadd, int pull, int *smaxuid )
{
	driver_t *tdriver = tctx->conf->driver, *sdriver = sctx->conf->driver;
	sync_rec_t *srec;
	message_t *msg;
	int nmsgs, uid;
	msg_data_t msgdata;

	for (nmsgs = 0, msg = sctx->msgs; msg; msg = msg->next)
		if (!(msg->status & M_PROCESSED)) {
			if (tops & OP_NEW) {
				debug( pull ? "new message %d on master\n" : "new message %d on slave\n", msg->uid );
				if ((tops & OP_EXPUNGE) && (msg->flags & F_DELETED)) {
					debug( pull ? "  not pulling - would be expunged anyway\n" : "  not pushing - would be expunged anyway\n" );
					msg->status |= M_NOT_SYNCED;
				} else {
					if ((msg->flags & F_FLAGGED) || !tconf->max_size || msg->size <= tconf->max_size) {
						debug( pull ? "  pulling it\n" : "  pushing it\n" );
						if (!nmsgs)
							info( pull ? "Pulling new messages..." : "Pushing new messages..." );
						else
							infoc( '.' );
						nmsgs++;
						msgdata.flags = msg->flags;
						switch (sdriver->fetch_msg( sctx, msg, &msgdata )) {
						case DRV_STORE_BAD: return pull ? SYNC_MASTER_BAD : SYNC_SLAVE_BAD;
						case DRV_BOX_BAD: return SYNC_FAIL;
						case DRV_MSG_BAD: /* ok */ msg->status |= M_NOT_SYNCED; continue;
						}
						msg->flags = msgdata.flags;
						switch (tdriver->store_msg( tctx, &msgdata, &uid )) {
						case DRV_STORE_BAD: return pull ? SYNC_SLAVE_BAD : SYNC_MASTER_BAD;
						default: return SYNC_FAIL;
						case DRV_OK: break;
						}
					} else {
						debug( pull ? "  not pulling - too big\n" : "  not pushing - too big\n" );
						msg->status |= M_NOT_SYNCED;
						uid = -1;
					}
					srec = nfmalloc( sizeof(*srec) );
					if (pull) {
						srec->muid = msg->uid;
						srec->suid = uid;
					} else {
						srec->muid = uid;
						srec->suid = msg->uid;
					}
					srec->flags = msg->flags;
					srec->status = 0;
					srec->next = 0;
					**srecadd = srec;
					*srecadd = &srec->next;
					fprintf( jfp, "+ %d %d %u\n", srec->muid, srec->suid, srec->flags );
					if (*smaxuid < msg->uid) {
						*smaxuid = msg->uid;
						fprintf( jfp, pull ? "( %d\n" : ") %d\n", msg->uid );
					}
				}
			} else
				msg->status |= M_NOT_SYNCED;
		}
	if (nmsgs)
		info( " %d messages\n", nmsgs );
	return SYNC_OK;
}

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

int
sync_boxes( store_t *mctx, const char *mname,
            store_t *sctx, const char *sname,
            channel_conf_t *chan )
{
	driver_t *mdriver = mctx->conf->driver, *sdriver = sctx->conf->driver;
	message_t *mmsg, *smsg, *nmmsg, *nsmsg;
	sync_rec_t *recs, *srec, **srecadd, *nsrec;
	char *dname, *jname, *nname, *lname, *s, *cmname, *csname;
	FILE *dfp, *jfp, *nfp;
	int mopts, sopts;
	int nom, nos, delm, dels, mex, sex;
	int muidval, suidval, smaxxuid, mmaxuid, smaxuid, minwuid, maxwuid;
	int t1, t2, t3;
	int lfd, ret, line, todel, delt, i, *mexcs, nmexcs, rmexcs;
	unsigned char nflags;
	struct stat st;
	struct flock lck;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[64];

	ret = SYNC_OK;
	recs = 0, srecadd = &recs;

	nmmsg = nsmsg = 0;

	mctx->uidvalidity = sctx->uidvalidity = 0;
	mopts = sopts = 0;
	makeopts( chan->sops, chan->slave, &sopts, chan->master, &mopts );
	makeopts( chan->mops, chan->master, &mopts, chan->slave, &sopts );
	if ((chan->sops & (OP_NEW|OP_RENEW)) && chan->max_messages)
		sopts |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	if (!mname || (mctx->conf->map_inbox && !strcmp( mctx->conf->map_inbox, mname )))
		mname = "INBOX";
	mctx->name = mname;
	mdriver->prepare( mctx, mopts );
	if (!sname || (sctx->conf->map_inbox && !strcmp( sctx->conf->map_inbox, sname )))
		sname = "INBOX";
	sctx->name = sname;
	sdriver->prepare( sctx, sopts );

	if (!strcmp( chan->sync_state ? chan->sync_state : global_sync_state, "*" )) {
		if (!sctx->path) {
			fprintf( stderr, "Error: store '%s' does not support in-box sync state\n", chan->slave->name );
			return SYNC_SLAVE_BAD;
		}
		nfasprintf( &dname, "%s/." EXE "state", sctx->path );
	} else {
		csname = clean_strdup( sname );
		if (chan->sync_state)
			nfasprintf( &dname, "%s%s", chan->sync_state, csname );
		else {
			cmname = clean_strdup( mname );
			nfasprintf( &dname, "%s:%s:%s_:%s:%s", global_sync_state,
			            chan->master->name, cmname, chan->slave->name, csname );
			free( cmname );
		}
		free( csname );
	}
	nfasprintf( &jname, "%s.journal", dname );
	nfasprintf( &nname, "%s.new", dname );
	nfasprintf( &lname, "%s.lock", dname );
	muidval = suidval = smaxxuid = mmaxuid = smaxuid = 0;
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
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
		         chan->master->name, mname, chan->slave->name, sname );
		ret = SYNC_FAIL;
		goto bail1;
	}
	if ((dfp = fopen( dname, "r" ))) {
		debug( "reading sync state %s ...\n", dname );
		if (fscanf( dfp, "%d:%d %d:%d:%d\n", &muidval, &mmaxuid, &suidval, &smaxxuid, &smaxuid) != 5) {
			fprintf( stderr, "Error: invalid sync state header in %s\n", dname );
			fclose( dfp );
			ret = SYNC_FAIL;
			goto bail;
		}
		line = 1;
		while (fgets( buf, sizeof(buf), dfp )) {
			line++;
			fbuf[0] = 0;
			if (sscanf( buf, "%d %d %15s\n", &t1, &t2, fbuf ) < 2) {
				fprintf( stderr, "Error: invalid sync state entry at %s:%d\n", dname, line );
				fclose( dfp );
				ret = SYNC_FAIL;
				goto bail;
			}
			srec = nfmalloc( sizeof(*srec) );
			srec->muid = t1;
			srec->suid = t2;
			s = fbuf;
			if (*s == 'X') {
				s++;
				srec->status = S_EXPIRED;
			} else
				srec->status = 0;
			srec->flags = parse_flags( s );
			debug( "  entry (%d,%d,%u,%s)\n", srec->muid, srec->suid, srec->flags, srec->status & S_EXPIRED ? "X" : "" );
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
		if (!stat( nname, &st )) {
			debug( "recovering journal ...\n" );
			line = 0;
			srec = recs;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (buf[0] == '^')
					srec = recs;
				else {
					if (buf[0] == '(' || buf[0] == ')' ?
					        (sscanf( buf + 2, "%d\n", &t1 ) != 1) :
					    buf[0] == '-' || buf[0] == '|' ?
						(sscanf( buf + 2, "%d %d\n", &t1, &t2 ) != 2) :
						(sscanf( buf + 2, "%d %d %d\n", &t1, &t2, &t3 ) != 3))
					{
						fprintf( stderr, "Error: malformed journal entry at %s:%d\n", jname, line );
						fclose( jfp );
						ret = SYNC_FAIL;
						goto bail;
					}
					if (buf[0] == '(')
						mmaxuid = t1;
					else if (buf[0] == ')')
						smaxuid = t1;
					else if (buf[0] == '|') {
						muidval = t1;
						suidval = t2;
					} else if (buf[0] == '+') {
						srec = nfmalloc( sizeof(*srec) );
						srec->muid = t1;
						srec->suid = t2;
						srec->flags = t3;
						debug( "  new entry(%d,%d,%u)\n", t1, t2, t3 );
						srec->status = 0;
						srec->next = 0;
						*srecadd = srec;
						srecadd = &srec->next;
					} else {
						for (; srec; srec = srec->next)
							if (srec->muid == t1 && srec->suid == t2)
								goto syncfnd;
						fprintf( stderr, "Error: journal entry at %s:%d refers to non-existing sync state entry\n", jname, line );
						fclose( jfp );
						ret = SYNC_FAIL;
						goto bail;
					  syncfnd:
						debug( "  entry(%d,%d,%u) ", srec->muid, srec->suid, srec->flags );
						switch (buf[0]) {
						case '-':
							debug( "killed\n" );
							srec->status = S_DEAD;
							break;
						case '<':
							debug( "master now %d\n", t3 );
							srec->muid = t3;
							break;
						case '>':
							debug( "slave now %d\n", t3 );
							srec->suid = t3;
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

	if (sctx->opts & OPEN_NEW)
		maxwuid = INT_MAX;
	else if (sctx->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = recs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->suid > maxwuid)
				maxwuid = srec->suid;
	} else
		maxwuid = 0;
	info( "Selecting slave %s... ", sname );
	debug( "selecting slave [1,%d]\n", maxwuid );
	switch (sdriver->select( sctx, (sctx->opts & OPEN_OLD) ? 1 : smaxuid + 1, maxwuid, 0, 0 )) {
	case DRV_STORE_BAD: ret = SYNC_SLAVE_BAD; goto bail;
	case DRV_BOX_BAD: ret = SYNC_FAIL; goto bail;
	}
	info( "%d messages, %d recent\n", sctx->count, sctx->recent );
	dump_box( sctx );

	if (suidval && suidval != sctx->uidvalidity) {
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

	mexcs = 0;
	nmexcs = rmexcs = 0;
	minwuid = INT_MAX;
	if (smaxxuid) {
		debug( "preparing master selection - max expired slave uid is %d\n", smaxxuid );
		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXPIRED) {
				if (!srec->suid || ((sctx->opts & OPEN_OLD) && !findmsg( sctx, srec->suid, &nsmsg, "slave" )))
					srec->status |= S_EXP_SLAVE;
				else if (minwuid > srec->muid)
					minwuid = srec->muid;
			} else if (smaxxuid < srec->suid && minwuid > srec->muid)
				minwuid = srec->muid;
		}
		debug( "  min non-orphaned master uid is %d\n", minwuid );
		fprintf( jfp, "^\n" ); /* if any S_EXP_SLAVE */
		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXP_SLAVE) {
				if (minwuid > srec->muid && mmaxuid >= srec->muid) {
					debug( "  -> killing (%d,%d)\n", srec->muid, srec->suid );
					srec->status = S_DEAD;
					fprintf( jfp, "- %d %d\n", srec->muid, srec->suid );
				} else if (srec->suid) {
					debug( "  -> orphaning (%d,[%d])\n", srec->muid, srec->suid );
					fprintf( jfp, "> %d %d 0\n", srec->muid, srec->suid );
					srec->suid = 0;
				}
			} else if (minwuid > srec->muid) {
				if (srec->suid < 0) {
					if (mmaxuid >= srec->muid) {
						debug( "  -> killing (%d,%d)\n", srec->muid, srec->suid );
						srec->status = S_DEAD;
						fprintf( jfp, "- %d %d\n", srec->muid, srec->suid );
					}
				} else if (srec->muid > 0 && srec->suid && (mctx->opts & OPEN_OLD) &&
				           (!(mctx->opts & OPEN_NEW) || mmaxuid >= srec->muid)) {
					if (nmexcs == rmexcs) {
						rmexcs = rmexcs * 2 + 100;
						mexcs = nfrealloc( mexcs, rmexcs * sizeof(int) );
					}
					mexcs[nmexcs++] = srec->muid;
				}
			}
		}
		debug( "  exception list is:" );
		for (i = 0; i < nmexcs; i++)
			debug( " %d", mexcs[i] );
		debug( "\n" );
	} else if (mctx->opts & OPEN_OLD)
		minwuid = 1;
	if (mctx->opts & OPEN_NEW) {
		if (minwuid > mmaxuid + 1)
			minwuid = mmaxuid + 1;
		maxwuid = INT_MAX;
	} else if (mctx->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = recs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->muid > maxwuid)
				maxwuid = srec->muid;
	} else
		maxwuid = 0;
	info( "Selecting master %s... ", mname );
	debug( "selecting master [%d,%d]\n", minwuid, maxwuid );
	switch (mdriver->select( mctx, minwuid, maxwuid, mexcs, nmexcs )) {
	case DRV_STORE_BAD: ret = SYNC_MASTER_BAD; goto finish;
	case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
	}
	info( "%d messages, %d recent\n", mctx->count, mctx->recent );
	dump_box( mctx );

	if (muidval && muidval != mctx->uidvalidity) {
		fprintf( stderr, "Error: UIDVALIDITY of master changed\n" );
		ret = SYNC_FAIL;
		goto finish;
	}

	if (!muidval || !suidval) {
		muidval = mctx->uidvalidity;
		suidval = sctx->uidvalidity;
		fprintf( jfp, "| %d %d\n", muidval, suidval );
	}

	info( "Synchronizing\n" );
	debug( "synchronizing old entries\n" );
	fprintf( jfp, "^\n" );
	for (srec = recs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		debug( "pair (%d,%d)\n", srec->muid, srec->suid );
		mmsg = findmsg( mctx, srec->muid, &nmmsg, "master" );
		smsg = (srec->status & S_EXP_SLAVE) ? 0 : findmsg( sctx, srec->suid, &nsmsg, "slave" );
		nom = !mmsg && (mctx->opts & OPEN_OLD);
		nos = !smsg && (sctx->opts & OPEN_OLD);
		if (nom && nos) {
			debug( "  vanished\n" );
			/* d.1) d.5) d.6) d.10) d.11) */
			srec->status = S_DEAD;
			fprintf( jfp, "- %d %d\n", srec->muid, srec->suid );
		} else {
			delm = nom && (srec->muid > 0);
			dels = nos && (srec->suid > 0);
			nflags = srec->flags;

			if ((ret = sync_old( chan->mops, sctx, mctx, chan->master, jfp, 0, &nflags, srec, smsg, mmsg, dels, delm )) != SYNC_OK ||
                            (ret = sync_old( chan->sops, mctx, sctx, chan->slave, jfp, 1, &nflags, srec, mmsg, smsg, delm, dels )) != SYNC_OK)
				goto finish;

			if (srec->flags != nflags) {
				debug( "  updating flags (%u -> %u)\n", srec->flags, nflags );
				srec->flags = nflags;
				fprintf( jfp, "* %d %d %u\n", srec->muid, srec->suid, nflags );
			}
			if (mmsg && (mmsg->flags & F_DELETED))
				srec->status |= S_DEL_MASTER;
			if (smsg && (smsg->flags & F_DELETED))
				srec->status |= S_DEL_SLAVE;
		}
	}

	debug( "synchronizing new entries\n" );
	if ((ret = sync_new( chan->mops, sctx, mctx, chan->master, jfp, &srecadd, 0, &smaxuid )) != SYNC_OK ||
	    (ret = sync_new( chan->sops, mctx, sctx, chan->slave, jfp, &srecadd, 1, &mmaxuid )) != SYNC_OK)
		goto finish;

	if ((chan->sops & (OP_NEW|OP_RENEW)) && chan->max_messages) {
		debug( "expiring excessive entries\n" );
		todel = sctx->count - chan->max_messages;
		for (smsg = sctx->msgs; smsg && todel > 0; smsg = smsg->next)
			if (!(smsg->status & M_DEAD) && (smsg->flags & F_DELETED))
				todel--;
		delt = 0;
		for (smsg = sctx->msgs; smsg && todel > 0; smsg = smsg->next) {
			if ((smsg->status & M_DEAD) || (smsg->flags & F_DELETED))
				continue;
			if ((smsg->flags & F_FLAGGED) || (smsg->status & M_NOT_SYNCED)) /* add M_DESYNCED? */
				todel--;
			else if (!(smsg->status & M_RECENT)) {
				smsg->status |= M_EXPIRED;
				delt++;
				todel--;
			}
		}
		if (delt) {
			fprintf( jfp, "^\n" );
			for (srec = recs; srec; srec = srec->next) {
				if (srec->status & (S_DEAD|S_EXPIRED))
					continue;
				smsg = findmsg( sctx, srec->suid, &nsmsg, "slave" );
				if (smsg && (smsg->status & M_EXPIRED)) {
					debug( "  expiring pair(%d,%d)\n", srec->muid, srec->suid );
					/* log first, so deletion can't be misinterpreted! */
					fprintf( jfp, "~ %d %d 1\n", srec->muid, srec->suid );
					if (smaxxuid < srec->suid)
						smaxxuid = srec->suid;
					srec->status |= S_EXPIRED;
					switch (sdriver->set_flags( sctx, smsg, 0, F_DELETED, 0 )) {
					case DRV_STORE_BAD: ret = SYNC_SLAVE_BAD; goto finish;
					case DRV_BOX_BAD: ret = SYNC_FAIL; goto finish;
					default: /* ok */ break;
					case DRV_OK: srec->status |= S_DEL_SLAVE;
					}
				}
			}
		}
	}

	/* Doing CLOSE here instead of EXPUNGE above saves network traffic.
	   But it costs more server power for single-file formats. And it
	   makes disk-full/quota-exceeded more probable. */
	mex = sex = 0;
	if (chan->mops & OP_EXPUNGE) {
		info( "Expunging master\n" );
		debug( "expunging master\n" );
		switch (expunge( mctx, sctx )) {
		case EX_STORE_BAD: ret = SYNC_MASTER_BAD; goto finish;
		case EX_RSTORE_BAD: ret = SYNC_SLAVE_BAD; goto finish;
		default: ret = SYNC_FAIL; break;
		case EX_OK: mex = 1;
		}
	}
	if (chan->sops & OP_EXPUNGE) {
		info( "Expunging slave\n" );
		debug( "expunging slave\n" );
		switch (expunge( sctx, mctx )) {
		case EX_STORE_BAD: ret = SYNC_SLAVE_BAD; goto finish;
		case EX_RSTORE_BAD: ret = SYNC_MASTER_BAD; goto finish;
		default: ret = SYNC_FAIL; break;
		case EX_OK: mex = 1;
		}
	}
	if (mex || sex) {
		/* This cleanup is not strictly necessary, as the next full sync
		   would throw out the dead entries anyway. But ... */

		minwuid = INT_MAX;
		if (smaxxuid) {
			debug( "preparing entry purge - max expired slave uid is %d\n", smaxxuid );
			for (srec = recs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!((srec->suid <= 0 || ((srec->status & S_DEL_SLAVE) && sex)) &&
				      (srec->muid <= 0 || ((srec->status & S_DEL_MASTER) && mex) || (srec->status & S_EXPIRED))) &&
				    smaxxuid < srec->suid && minwuid > srec->muid)
					minwuid = srec->muid;
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
		}

		fprintf( jfp, "^\n" );
		for (srec = recs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->suid <= 0 || ((srec->status & S_DEL_SLAVE) && sex)) {
				if (srec->muid <= 0 || ((srec->status & S_DEL_MASTER) && mex)) {
					debug( "  -> killing (%d,%d)\n", srec->muid, srec->suid );
					srec->status = S_DEAD;
					fprintf( jfp, "- %d %d\n", srec->muid, srec->suid );
				} else if (srec->status & S_EXPIRED) {
					if (mmaxuid >= srec->muid && minwuid > srec->muid) {
						debug( "  -> killing (%d,%d)\n", srec->muid, srec->suid );
						srec->status = S_DEAD;
						fprintf( jfp, "- %d %d\n", srec->muid, srec->suid );
					} else if (srec->suid) {
						debug( "  -> orphaning (%d,[%d])\n", srec->muid, srec->suid );
						fprintf( jfp, "> %d %d 0\n", srec->muid, srec->suid );
						srec->suid = 0;
					}
				}
			}
		}
	}

  finish:
	fprintf( nfp, "%d:%d %d:%d:%d\n", muidval, mmaxuid, suidval, smaxxuid, smaxuid );
	for (srec = recs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		fprintf( nfp, "%d %d %s%s\n", srec->muid, srec->suid,
		         srec->status & S_EXPIRED ? "X" : "", fbuf );
	}

	fclose( nfp );
	fclose( jfp );
	/* order is important! */
	rename( nname, dname );
	unlink( jname );

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

