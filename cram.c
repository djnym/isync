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
#include "isync.h"

#if HAVE_LIBSSL

#include <string.h>
#include <openssl/hmac.h>

#define ENCODED_SIZE(n)	(4*((n+2)/3))

static char
hexchar (unsigned int b)
{
    if (b < 10)
	return '0' + b;
    return 'a' + (b - 10);
}

char *
cram (const char *challenge, const char *user, const char *pass)
{
    HMAC_CTX hmac;
    char hash[16];
    char hex[33];
    int i;
    unsigned int hashlen = sizeof (hash);
    char buf[256];
    int len = strlen (challenge);
    char *response = calloc (1, 1 + len);
    char *final;

    /* response will always be smaller than challenge because we are
     * decoding.
     */
    len = EVP_DecodeBlock ((unsigned char *) response, (unsigned char *) challenge, strlen (challenge));

    HMAC_Init (&hmac, (unsigned char *) pass, strlen (pass), EVP_md5 ());
    HMAC_Update (&hmac, (unsigned char *) response, strlen(response));
    HMAC_Final (&hmac, (unsigned char *) hash, &hashlen);

    assert (hashlen == sizeof (hash));

    free (response);

    hex[32] = 0;
    for (i = 0; i < 16; i++)
    {
	hex[2 * i] = hexchar ((hash[i] >> 4) & 0xf);
	hex[2 * i + 1] = hexchar (hash[i] & 0xf);
    }

    snprintf (buf, sizeof (buf), "%s %s", user, hex);

    len = strlen (buf);
    len = ENCODED_SIZE (len) + 1;
    final = malloc (len);
    final[len - 1] = 0;

    assert (EVP_EncodeBlock ((unsigned char *) final, (unsigned char *) buf, strlen (buf)) == len - 1);

    return final;
}

#endif
