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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "isync.h"

static char *
skip_string (char *s)
{
    while (*s && *s != '"')
	s++;
    return s;
}

list_t *
parse_list (char *s, char **end)
{
    int level = 1;
    list_t *cur;
    list_t **list;
    char *b;

    cur = calloc (1, sizeof (list_t));
    while (isspace ((unsigned char) *s))
	s++;
    if (*s == '(')
    {
	/* start of list.  find the end of the list */
	s++;
	b = s;			/* save beginning */
	cur->val = LIST;
	while (*s)
	{
	    if (*s == '(')
	    {
		level++;
	    }
	    else if (*s == ')')
	    {
		level--;
		if (level == 0)
		    break;
	    }
	    else if (*s == '"')
	    {
		s = skip_string (s + 1);
		if (!*s)
		{
		    /* parse error */
		    free (cur);
		    return NULL;
		}
	    }
	    s++;
	}
	if (level != 0)
	{
	    free (cur);		/* parse error */
	    return NULL;
	}
	*s++ = 0;

	list = &cur->child;
	while (*b)
	{
	    *list = parse_list (b, &b);
	    if (*list == NULL)
	    {
		/* parse error */
		free (cur);
		return NULL;
	    }
	    while (*list)
		list = &(*list)->next;
	}
    }
    else if (*s == '"')
    {
	/* quoted string */
	s++;
	cur->val = s;
	s = skip_string (s);
	if (!*s)
	{
	    /* parse error */
	    free (cur);
	    return NULL;
	}
	*s++ = 0;
	cur->val = strdup (cur->val);
    }
    else
    {
	/* atom */
	cur->val = s;
	while (*s && !isspace ((unsigned char) *s))
	    s++;
	if (*s)
	    *s++ = 0;
	if (strcmp ("NIL", cur->val))
	    cur->val = strdup (cur->val);
	else
	    cur->val = NIL;
    }
    if (end)
	*end = s;
    return cur;
}

int
is_atom (list_t * list)
{
    return (list && list->val && list->val != NIL && list->val != LIST);
}

int
is_list (list_t * list)
{
    return (list && list->val == LIST);
}

int
is_nil (list_t * list)
{
    return (list && list->val == NIL);
}

void
free_list (list_t * list)
{
    list_t *tmp;

    while (list)
    {
	tmp = list;
	list = list->next;
	if (is_list (list))
	    free_list (tmp->child);
	else if (is_atom (tmp))
	    free (tmp->val);
	free (tmp);
    }
}

#if TEST
int
main (int argc, char **argv)
{
    char buf[256];
    list_t *list;

    strcpy (buf,
	    "((compound list) atom NIL \"string with a (\" (another list))");
    list = parse_list (buf, 0);
}
#endif
