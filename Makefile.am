bin_PROGRAMS=isync
isync_SOURCES=main.c imap.c sync.c maildir.c isync.h list.c cram.c config.c \
	      debug.h
isync_LDADD=@DEBUGOBJ@
isync_DEPENDENCIES=@DEBUGOBJ@
EXTRA_isync_SOURCES=debug.c
man_MANS=isync.1
EXTRA_DIST=sample.isyncrc $(man_MANS)
INCLUDES=$(RPM_OPT_FLAGS)

log:
	rcs2log -h sigpipe.org | sed 's;/home/cvs/isync/;;g' > ChangeLog

isync.html: isync.1
	groff -Thtml -man isync.1 > isync.html

rpm:
	make dist
	cp isync-$(VERSION).tar.gz /usr/src/rpm/SOURCES
	rpm -ba --target=i586 --clean isync.spec
