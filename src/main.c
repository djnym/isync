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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int Pid;		/* for maildir and imap */
char Hostname[256];	/* for maildir */
const char *Home;	/* for config */

static void
version( void )
{
	puts( PACKAGE " " VERSION );
	exit( 0 );
}

static void
usage( int code )
{
	fputs(
PACKAGE " " VERSION " - mailbox synchronizer\n"
"Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>\n"
"Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>\n"
"Copyright (C) 2004 Theodore Ts'o <tytso@mit.edu>\n"
"usage:\n"
" " EXE " [flags] {{channel[:box,...]|group} ...|-a}\n"
"  -a, --all		operate on all defined channels\n"
"  -l, --list		list mailboxes instead of syncing them\n"
"  -n, --new		propagate new messages\n"
"  -d, --delete		propagate message deletions\n"
"  -f, --flags		propagate message flag changes\n"
"  -N, --renew		propagate previously not propagated new messages\n"
"  -L, --pull		propagate from master to slave\n"
"  -H, --push		propagate from slave to master\n"
"  -C, --create		create mailboxes if nonexistent\n"
"  -X, --expunge		expunge	deleted messages\n"
"  -c, --config CONFIG	read an alternate config file (default: ~/." EXE "rc)\n"
"  -D, --debug		print debugging messages\n"
"  -V, --verbose		verbose mode (display network traffic)\n"
"  -q, --quiet		don't display progress info\n"
"  -v, --version		display version\n"
"  -h, --help		display this help message\n"
"\nIf neither --pull nor --push are specified, both are active.\n"
"If neither --new, --delete, --flags nor --renew are specified, all are active.\n"
"Direction and operation can be concatenated like --pull-new, etc.\n"
"--create and --expunge can be suffixed with -master/-slave. Read the man page.\n"
"\nSupported mailbox formats are: IMAP4rev1, Maildir\n"
"\nCompile time options:\n"
#if HAVE_LIBSSL
"  +HAVE_LIBSSL\n"
#else
"  -HAVE_LIBSSL\n"
#endif
	, code ? stderr : stdout );
	exit( code );
}

static int
matches( const char *t, const char *p )
{
	for (;;) {
		if (!*p)
			return !*t;
		if (*p == '*') {
			p++;
			do {
				if (matches( t, p ))
					return 1;
			} while (*t++);
			return 0;
		} else if (*p == '%') {
			p++;
			do {
				if (*t == '.' || *t == '/') /* this is "somewhat" hacky ... */
					return 0;
				if (matches( t, p ))
					return 1;
			} while (*t++);
			return 0;
		} else {
			if (*p != *t)
				return 0;
			p++, t++;
		}
	}
}

static string_list_t *
filter_boxes( string_list_t *boxes, string_list_t *patterns )
{
	string_list_t *nboxes = 0, *cpat;
	const char *ps;
	int not, fnot;

	for (; boxes; boxes = boxes->next) {
		fnot = 1;
		for (cpat = patterns; cpat; cpat = cpat->next) {
			ps = cpat->string;
			if (*ps == '!') {
				ps++;
				not = 1;
			} else
				not = 0;
			if (matches( boxes->string, ps )) {
				fnot = not;
				break;
			}
		}
		if (!fnot)
			add_string_list( &nboxes, boxes->string );
	}
	return nboxes;
}

static void
merge_actions( channel_conf_t *chan, int mops, int sops, int have, int mask, int def )
{
	if (mops & have) {
		chan->mops &= ~mask;
		chan->mops |= mops & mask;
		chan->sops &= ~mask;
		chan->sops |= sops & mask;
	} else if (!(chan->mops & have)) {
		if (global_mops & have) {
			chan->mops |= global_mops & mask;
			chan->sops |= global_sops & mask;
		} else {
			chan->mops |= def;
			chan->sops |= def;
		}
	}
}

int
main( int argc, char **argv )
{
	channel_conf_t *chan;
	store_conf_t *mconf, *sconf;
	group_conf_t *group;
	driver_t *mdriver, *sdriver;
	store_t *mctx, *sctx;
	string_list_t *umboxes, *usboxes, *mboxes, *sboxes, *mbox, *sbox, **mboxp, **sboxp, *cboxes, *chanptr;
	char *config = 0, *channame, *boxlist, *opt, *ochar;
	int all = 0, list = 0, cops = 0, mops = 0, sops = 0, gumboxes, gusboxes;
	int oind, ret, op, multiple, pseudo = 0;

	gethostname( Hostname, sizeof(Hostname) );
	if ((ochar = strchr( Hostname, '.' )))
		*ochar = 0;
	Pid = getpid();
	if (!(Home = getenv("HOME"))) {
		fputs( "Fatal: $HOME not set\n", stderr );
		return 1;
	}
	arc4_init();

	for (oind = 1, ochar = 0; oind < argc; ) {
		if (!ochar || !*ochar) {
			if (argv[oind][0] != '-')
				break;
			if (argv[oind][1] == '-') {
				opt = argv[oind++] + 2;
				if (!*opt)
					break;
				if (!strcmp( opt, "config" )) {
					if (oind >= argc) {
						fprintf( stderr, "--config requires an argument.\n" );
						return 1;
					}
					config = argv[oind++];
				} else if (!memcmp( opt, "config=", 7 ))
					config = opt + 7;
				else if (!strcmp( opt, "all" ))
					all = 1;
				else if (!strcmp( opt, "list" ))
					list = 1;
				else if (!strcmp( opt, "help" ))
					usage( 0 );
				else if (!strcmp( opt, "version" ))
					version();
				else if (!strcmp( opt, "quiet" ))
					Quiet++;
				else if (!strcmp( opt, "verbose" )) {
					Verbose = 1;
					if (!Quiet)
						Quiet = 1;
				} else if (!strcmp( opt, "debug" )) {
					Debug = 1;
					if (!Quiet)
						Quiet = 1;
				} else if (!strcmp( opt, "pull" ))
					cops |= XOP_PULL, mops |= XOP_HAVE_TYPE;
				else if (!strcmp( opt, "push" ))
					cops |= XOP_PUSH, mops |= XOP_HAVE_TYPE;
				else if (!memcmp( opt, "create", 6 )) {
					opt += 6;
					op = OP_CREATE|XOP_HAVE_CREATE;
				  lcop:
					if (!*opt)
						cops |= op;
					else if (!strcmp( opt, "-master" ))
						mops |= op, ochar++;
					else if (!strcmp( opt, "-slave" ))
						sops |= op, ochar++;
					else
						goto badopt;
					mops |= op & (XOP_HAVE_CREATE|XOP_HAVE_EXPUNGE);
				} else if (!memcmp( opt, "expunge", 7 )) {
					opt += 7;
					op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
					goto lcop;
				} else if (!strcmp( opt, "no-expunge" ))
					mops |= XOP_HAVE_EXPUNGE;
				else if (!strcmp( opt, "no-create" ))
					mops |= XOP_HAVE_CREATE;
				else if (!strcmp( opt, "full" ))
					mops |= XOP_HAVE_TYPE|XOP_PULL|XOP_PUSH;
				else if (!strcmp( opt, "noop" ))
					mops |= XOP_HAVE_TYPE;
				else if (!memcmp( opt, "pull", 4 )) {
					op = XOP_PULL;
				  lcac:
					opt += 4;
					if (!*opt)
						cops |= op;
					else if (*opt == '-') {
						opt++;
						goto rlcac;
					} else
						goto badopt;
				} else if (!memcmp( opt, "push", 4 )) {
					op = XOP_PUSH;
					goto lcac;
				} else {
					op = 0;
				  rlcac:
					if (!strcmp( opt, "new" ))
						op |= OP_NEW;
					else if (!strcmp( opt, "renew" ))
						op |= OP_RENEW;
					else if (!strcmp( opt, "delete" ))
						op |= OP_DELETE;
					else if (!strcmp( opt, "flags" ))
						op |= OP_FLAGS;
					else {
					  badopt:
						fprintf( stderr, "Unknown option '%s'\n", argv[oind - 1] );
						return 1;
					}
					switch (op & XOP_MASK_DIR) {
					case XOP_PULL: sops |= op & OP_MASK_TYPE; break;
					case XOP_PUSH: mops |= op & OP_MASK_TYPE; break;
					default: cops |= op; break;
					}
					mops |= XOP_HAVE_TYPE;
				}
				continue;
			}
			ochar = argv[oind++] + 1;
			if (!*ochar) {
				fprintf( stderr, "Invalid option '-'\n" );
				return 1;
			}
		}
		switch (*ochar++) {
		case 'a':
			all = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'c':
			if (*ochar == 'T') {
				ochar++;
				pseudo = 1;
			}
			if (oind >= argc) {
				fprintf( stderr, "-c requires an argument.\n" );
				return 1;
			}
			config = argv[oind++];
			break;
		case 'C':
			op = OP_CREATE|XOP_HAVE_CREATE;
		  cop:
			if (*ochar == 'm')
				mops |= op, ochar++;
			else if (*ochar == 's')
				sops |= op, ochar++;
			else if (*ochar == '-')
				ochar++;
			else
				cops |= op;
			mops |= op & (XOP_HAVE_CREATE|XOP_HAVE_EXPUNGE);
			break;
		case 'X':
			op = OP_EXPUNGE|XOP_HAVE_EXPUNGE;
			goto cop;
		case 'F':
			cops |= XOP_PULL|XOP_PUSH;
		case '0':
			mops |= XOP_HAVE_TYPE;
			break;
		case 'n':
		case 'd':
		case 'f':
		case 'N':
			--ochar;
			op = 0;
		  cac:
			for (;; ochar++) {
				if (*ochar == 'n')
					op |= OP_NEW;
				else if (*ochar == 'd')
					op |= OP_DELETE;
				else if (*ochar == 'f')
					op |= OP_FLAGS;
				else if (*ochar == 'N')
					op |= OP_RENEW;
				else
					break;
			}
			if (op & OP_MASK_TYPE)
				switch (op & XOP_MASK_DIR) {
				case XOP_PULL: sops |= op & OP_MASK_TYPE; break;
				case XOP_PUSH: mops |= op & OP_MASK_TYPE; break;
				default: cops |= op; break;
				}
			else
				cops |= op;
			mops |= XOP_HAVE_TYPE;
			break;
		case 'L':
			op = XOP_PULL;
			goto cac;
		case 'H':
			op = XOP_PUSH;
			goto cac;
		case 'q':
			Quiet++;
			break;
		case 'V':
			Verbose = 1;
			if (!Quiet)
				Quiet = 1;
			break;
		case 'D':
			Debug = 1;
			if (!Quiet)
				Quiet = 1;
			break;
		case 'v':
			version();
		case 'h':
			usage( 0 );
		default:
			fprintf( stderr, "Unknown option '-%c'\n", *(ochar - 1) );
			return 1;
		}
	}

	if (merge_ops( cops, &mops, &sops ))
		return 1;

	if (load_config( config, pseudo ))
		return 1;

	if (!all && !argv[oind]) {
		fputs( "No channel specified. Try '" EXE " -h'\n", stderr );
		return 1;
	}
	if (!channels) {
		fputs( "No channels defined. Try 'man " EXE "'\n", stderr );
		return 1;
	}

	ret = 0;
	chan = channels;
	chanptr = 0;
	mctx = sctx = 0;
	mconf = sconf = 0;	/* make-gcc-happy */
	mdriver = sdriver = 0;	/* make-gcc-happy */
	gumboxes = gusboxes = 0;
	umboxes = usboxes = 0;
	if (all)
		multiple = channels->next != 0;
	else if (argv[oind + 1])
		multiple = 1;
	else {
		multiple = 0;
		for (group = groups; group; group = group->next)
			if (!strcmp( group->name, argv[oind] )) {
				multiple = 1;
				break;
			}
	}
	for (;;) {
		boxlist = 0;
		if (!all) {
			if (chanptr)
				channame = chanptr->string;
			else {
				for (group = groups; group; group = group->next)
					if (!strcmp( group->name, argv[oind] )) {
						chanptr = group->channels;
						channame = chanptr->string;
						goto gotgrp;
					}
				channame = argv[oind];
			  gotgrp: ;
			}
			if ((boxlist = strchr( channame, ':' )))
				*boxlist++ = 0;
			for (chan = channels; chan; chan = chan->next)
				if (!strcmp( chan->name, channame ))
					goto gotchan;
			fprintf( stderr, "No channel or group named '%s' defined.\n", channame );
			ret = 1;
			goto gotnone;
		  gotchan: ;
		}
		merge_actions( chan, mops, sops, XOP_HAVE_TYPE, OP_MASK_TYPE, OP_MASK_TYPE );
		merge_actions( chan, mops, sops, XOP_HAVE_CREATE, OP_CREATE, 0 );
		merge_actions( chan, mops, sops, XOP_HAVE_EXPUNGE, OP_EXPUNGE, 0 );

		mboxes = sboxes = cboxes = 0;
		/* possible todo: handle master <-> slave swaps */
		if (mctx) {
			if (mconf == chan->master)
				goto gotmctx;
			free_string_list( umboxes );
			umboxes = 0;
			gumboxes = 0;
			if (mconf->driver != chan->master->driver) {
				mdriver->close_store( mctx );
				mctx = 0;
			}
		}
		mconf = chan->master;
		mdriver = mconf->driver;
		if (!(mctx = mdriver->open_store( chan->master, mctx ))) {
			ret = 1;
			goto next;
		}
	  gotmctx:
		if (sctx) {
			if (sconf == chan->slave)
				goto gotsctx;
			free_string_list( usboxes );
			usboxes = 0;
			gusboxes = 0;
			if (sconf->driver != chan->slave->driver) {
				sdriver->close_store( sctx );
				sctx = 0;
			}
		}
		sconf = chan->slave;
		sdriver = sconf->driver;
		if (!(sctx = sdriver->open_store( chan->slave, sctx ))) {
			ret = 1;
			goto next;
		}
	  gotsctx:
		info( "Channel %s\n", chan->name );
		if (list && multiple)
			printf( "%s:\n", chan->name );
		if (boxlist) {
			for (boxlist = strtok( boxlist, ",\n" ); boxlist; boxlist = strtok( 0, ",\n" ))
				if (list)
					puts( boxlist );
				else
					switch (sync_boxes( mctx, boxlist, sctx, boxlist, chan )) {
					case SYNC_MASTER_BAD: goto screwm;
					case SYNC_SLAVE_BAD: goto screws;
					case SYNC_FAIL: ret = 1;
					}
		} else if (chan->patterns) {
			if (!gumboxes) {
				if (mdriver->list( mctx, &umboxes ) != DRV_OK) {
				  screwm:
					mdriver->close_store( mctx );
					free_string_list( umboxes );
					umboxes = 0;
					gumboxes = 0;
					mctx = 0;
					ret = 1;
					goto next;
				} else {
					gumboxes = 1;
					if (mctx->conf->map_inbox)
						add_string_list( &umboxes, mctx->conf->map_inbox );
				}
			}
			if (!gusboxes) {
				if (sdriver->list( sctx, &usboxes ) != DRV_OK) {
				  screws:
					sdriver->close_store( sctx );
					free_string_list( usboxes );
					usboxes = 0;
					gusboxes = 0;
					sctx = 0;
					ret = 1;
					goto next;
				} else {
					gusboxes = 1;
					if (sctx->conf->map_inbox)
						add_string_list( &usboxes, sctx->conf->map_inbox );
				}
			}
			mboxes = filter_boxes( umboxes, chan->patterns );
			sboxes = filter_boxes( usboxes, chan->patterns );
			for (mboxp = &mboxes; (mbox = *mboxp); ) {
				for (sboxp = &sboxes; (sbox = *sboxp); sboxp = &sbox->next)
					if (!strcmp( sbox->string, mbox->string )) {
						*sboxp = sbox->next;
						free( sbox );
						*mboxp = mbox->next;
						mbox->next = cboxes;
						cboxes = mbox;
						goto gotdupe;
					}
				mboxp = &mbox->next;
			  gotdupe: ;
			}
			for (mbox = cboxes; mbox; mbox = mbox->next)
				if (list)
					puts( mbox->string );
				else
					switch (sync_boxes( mctx, mbox->string, sctx, mbox->string, chan )) {
					case SYNC_MASTER_BAD: goto screwm;
					case SYNC_SLAVE_BAD: goto screws;
					case SYNC_FAIL: ret = 1;
					}
			if ((chan->sops & OP_MASK_TYPE) && (chan->sops & OP_CREATE)) {
				for (mbox = mboxes; mbox; mbox = mbox->next)
					if (list)
						puts( mbox->string );
					else
						switch (sync_boxes( mctx, mbox->string, sctx, mbox->string, chan )) {
						case SYNC_MASTER_BAD: goto screwm;
						case SYNC_SLAVE_BAD: goto screws;
						case SYNC_FAIL: ret = 1;
						}
			}
			if ((chan->mops & OP_MASK_TYPE) && (chan->mops & OP_CREATE)) {
				for (mbox = sboxes; mbox; mbox = mbox->next)
					if (list)
						puts( mbox->string );
					else
						switch (sync_boxes( mctx, mbox->string, sctx, mbox->string, chan )) {
						case SYNC_MASTER_BAD: goto screwm;
						case SYNC_SLAVE_BAD: goto screws;
						case SYNC_FAIL: ret = 1;
						}
			}
		} else
			if (list)
				printf( "%s <=> %s\n", chan->master_name, chan->slave_name );
			else
				switch (sync_boxes( mctx, chan->master_name, sctx, chan->slave_name, chan )) {
				case SYNC_MASTER_BAD: goto screwm;
				case SYNC_SLAVE_BAD: goto screws;
				case SYNC_FAIL: ret = 1;
				}

	  next:
		free_string_list( cboxes );
		free_string_list( mboxes );
		free_string_list( sboxes );
		if (all) {
			if (!(chan = chan->next))
				break;
		} else {
			if (chanptr && (chanptr = chanptr->next))
				continue;
		  gotnone:
			if (!argv[++oind])
				break;
		}
	}
	free_string_list( usboxes );
	if (sctx)
		sdriver->close_store( sctx );
	free_string_list( umboxes );
	if (mctx)
		mdriver->close_store( mctx );

	return ret;
}
