bin_PROGRAMS = isync

isync_SOURCES = main.c config.c convert.c util.c
isync_LDADD = -ldb
noinst_HEADERS = isync.h

man_MANS = isync.1
EXTRA_DIST = isyncrc.sample $(man_MANS)
