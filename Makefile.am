SUBDIRS = debian src
man_MANS = isync.1
EXTRA_DIST = isyncrc.sample isync.spec.in $(man_MANS)
DISTCLEANFILES = *~ build-stamp configure-stamp

log:
	rcs2log -u "me	Michael Elkins	me@sigpipe.org" \
		-u "melkins	Michael Elkins	me@sigpipe.org" \
		-u "ossi	Oswald Buddenhagen	ossi@users.sf.net" \
	    -l 79 > ChangeLog

rpm:
	make dist
	cp $(PACKAGE)-$(VERSION).tar.gz /usr/src/rpm/SOURCES
	rpm -ba --target=i586 --clean isync.spec
