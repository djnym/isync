bin_PROGRAMS=isync
isync_SOURCES=main.c imap.c sync.c maildir.c isync.h
man_MANS=isync.1
EXTRA_DIST=sample.isyncrc $(man_MANS)

log:
	rcs2log -h sigipe.org | sed 's;/home/cvs/isync/;;g' > ChangeLog
