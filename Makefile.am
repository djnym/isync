bin_PROGRAMS=isync
isync_SOURCES=main.c imap.c sync.c maildir.c isync.h list.c cram.c config.c
man_MANS=isync.1
EXTRA_DIST=sample.isyncrc $(man_MANS)
INCLUDES=$(RPM_OPT_FLAGS)

log:
	rcs2log -h sigipe.org | sed 's;/home/cvs/isync/;;g' > ChangeLog

isync.html: isync.1
	groff -Thtml -man isync.1 > isync.html

rpm:
	make dist
	cp isync-$(VERSION).tar.gz /usr/src/RPM/SOURCES
	rpm -ba --target=i586 --clean isync.spec
