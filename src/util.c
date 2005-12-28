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
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <ctype.h>

int Verbose, Quiet, Debug;

void
debug( const char *msg, ... )
{
	va_list va;

	if (Debug) {
		va_start( va, msg );
		vprintf( msg, va );
		va_end( va );
		fflush( stdout );
	}
}

void
info( const char *msg, ... )
{
	va_list va;

	if (!Quiet) {
		va_start( va, msg );
		vprintf( msg, va );
		va_end( va );
		fflush( stdout );
	}
}

void
infoc( char c )
{
	if (!Quiet) {
		putchar( c );
		fflush( stdout );
	}
}

void
warn( const char *msg, ... )
{
	va_list va;

	if (Quiet < 2) {
		va_start( va, msg );
		vfprintf( stderr, msg, va );
		va_end( va );
	}
}

char *
next_arg( char **s )
{
	char *ret;

	if (!s || !*s)
		return 0;
	while (isspace( (unsigned char) **s ))
		(*s)++;
	if (!**s) {
		*s = 0;
		return 0;
	}
	if (**s == '"') {
		++*s;
		ret = *s;
		*s = strchr( *s, '"' );
	} else {
		ret = *s;
		while (**s && !isspace( (unsigned char) **s ))
			(*s)++;
	}
	if (*s) {
		if (**s)
			*(*s)++ = 0;
		if (!**s)
			*s = 0;
	}
	return ret;
}

void
add_string_list( string_list_t **list, const char *str )
{
	string_list_t *elem;
	int len;

	len = strlen( str );
	elem = nfmalloc( sizeof(*elem) + len );
	elem->next = *list;
	*list = elem;
	memcpy( elem->string, str, len + 1 );
}

void
free_string_list( string_list_t *list )
{
	string_list_t *tlist;

	for (; list; list = tlist) {
		tlist = list->next;
		free( list );
	}
}

void
free_generic_messages( message_t *msgs )
{
	message_t *tmsg;

	for (; msgs; msgs = tmsg) {
		tmsg = msgs->next;
		free( msgs );
	}
}

void
strip_cr( msg_data_t *msgdata )
{
	int i, o;

	if (msgdata->crlf) {
		for (i = o = 0; i < msgdata->len; i++)
			if (msgdata->data[i] != '\r')
				msgdata->data[o++] = msgdata->data[i];
		msgdata->len = o;
		msgdata->crlf = 0;
	}
}

#ifndef HAVE_VASPRINTF
static int
vasprintf( char **strp, const char *fmt, va_list ap )
{
	int len;
	char tmp[1024];

	if ((len = vsnprintf( tmp, sizeof(tmp), fmt, ap )) < 0 || !(*strp = malloc( len + 1 )))
		return -1;
	if (len >= (int)sizeof(tmp))
		vsprintf( *strp, fmt, ap );
	else
		memcpy( *strp, tmp, len + 1 );
	return len;
}
#endif

void
oob( void )
{
	fputs( "Fatal: buffer too small. Please report a bug.\n", stderr );
	abort();
}

int
nfsnprintf( char *buf, int blen, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	if (blen <= 0 || (unsigned)(ret = vsnprintf( buf, blen, fmt, va )) >= (unsigned)blen)
		oob();
	va_end( va );
	return ret;
}

static void ATTR_NORETURN
oom( void )
{
	fputs( "Fatal: Out of memory\n", stderr );
	abort();
}

void *
nfmalloc( size_t sz )
{
	void *ret;

	if (!(ret = malloc( sz )))
		oom();
	return ret;
}

void *
nfcalloc( size_t sz )
{
	void *ret;

	if (!(ret = calloc( sz, 1 )))
		oom();
	return ret;
}

void *
nfrealloc( void *mem, size_t sz )
{
	char *ret;

	if (!(ret = realloc( mem, sz )) && sz)
		oom();
	return ret;
}

char *
nfstrdup( const char *str )
{
	char *ret;

	if (!(ret = strdup( str )))
		oom();
	return ret;
}

int
nfvasprintf( char **str, const char *fmt, va_list va )
{
	int ret = vasprintf( str, fmt, va );
	if (ret < 0)
		oom();
	return ret;
}

int
nfasprintf( char **str, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	ret = nfvasprintf( str, fmt, va );
	va_end( va );
	return ret;
}

/*
static struct passwd *
cur_user( void )
{
	char *p;
	struct passwd *pw;
	uid_t uid;

	uid = getuid();
	if ((!(p = getenv("LOGNAME")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    (!(p = getenv("USER")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    !(pw = getpwuid( uid )))
	{
		fputs ("Cannot determinate current user\n", stderr);
		return 0;
	}
	return pw;
}
*/

static char *
my_strndup( const char *s, size_t nchars )
{
	char *r = nfmalloc( nchars + 1 );
	memcpy( r, s, nchars );
	r[nchars] = 0;
	return r;
}

char *
expand_strdup( const char *s )
{
	struct passwd *pw;
	const char *p, *q;
	char *r;

	if (*s == '~') {
		s++;
		if (!*s) {
			p = 0;
			q = Home;
		} else if (*s == '/') {
			p = s;
			q = Home;
		} else {
			if ((p = strchr( s, '/' ))) {
				r = my_strndup( s, (int)(p - s) );
				pw = getpwnam( r );
				free( r );
			} else
				pw = getpwnam( s );
			if (!pw)
				return 0;
			q = pw->pw_dir;
		}
		nfasprintf( &r, "%s%s", q, p ? p : "" );
		return r;
	} else
		return nfstrdup( s );
}

static int
compare_ints( const void *l, const void *r )
{
	return *(int *)l - *(int *)r;
}

void
sort_ints( int *arr, int len )
{
	qsort( arr, len, sizeof(int), compare_ints );
}


static struct {
	unsigned char i, j, s[256];
} rs;

void
arc4_init( void )
{
	int i, fd;
	unsigned char j, si, dat[128];

	if ((fd = open( "/dev/urandom", O_RDONLY )) < 0 && (fd = open( "/dev/random", O_RDONLY )) < 0) {
		fprintf( stderr, "Fatal: no random number source available.\n" );
		exit( 3 );
	}
	if (read( fd, dat, 128 ) != 128) {
		fprintf( stderr, "Fatal: cannot read random number source.\n" );
		exit( 3 );
	}
	close( fd );

	for (i = 0; i < 256; i++)
		rs.s[i] = i;
	for (i = j = 0; i < 256; i++) {
		si = rs.s[i];
		j += si + dat[i & 127];
		rs.s[i] = rs.s[j];
		rs.s[j] = si;
	}
	rs.i = rs.j = 0;

	for (i = 0; i < 256; i++)
		arc4_getbyte();
}

unsigned char
arc4_getbyte( void )
{
	unsigned char si, sj;

	rs.i++;
	si = rs.s[rs.i];
	rs.j += si;
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;
	return rs.s[(si + sj) & 0xff];
}
