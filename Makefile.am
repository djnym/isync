SUBDIRS = debian src
man_MANS = isync.1
EXTRA_DIST = isyncrc.sample isync.spec $(man_MANS)
DISTCLEANFILES = *~ build-stamp configure-stamp

log:
	@echo "me:'Michael Elkins <me@sigpipe.org>'" > .usermap
	@echo "melkins:'Michael Elkins <me@sigpipe.org>'" >> .usermap
	@echo "ossi:'Oswald Buddenhagen <ossi@users.sf.net>'" >> .usermap
	cvs2cl -U .usermap --no-wrap --separate-header
	@rm -f .usermap ChangeLog.bak

rpm:
	make dist
	cp $(PACKAGE)-$(VERSION).tar.gz /usr/src/rpm/SOURCES
	rpm -ba --target=i586 --clean isync.spec
