#! /bin/sh
# $Id$
set -e -v
aclocal
automake --add-missing
autoconf
./configure "$@"
