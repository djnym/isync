#!/bin/sh
# $Id$
aclocal
if test $? -ne 0; then
	exit
fi
automake --add-missing
if test $? -ne 0; then
	exit
fi
autoconf
if test $? -ne 0; then
	exit
fi
./configure $@
