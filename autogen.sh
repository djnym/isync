#! /bin/sh
# $Id$
set -e -v
aclocal
autoheader
automake --add-missing
autoconf
./configure "$@"
