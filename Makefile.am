SUBDIRS = src
man_MANS = isync.1
EXTRA_DIST = debian isyncrc.sample isync.spec $(man_MANS)

log:
	@echo "me:'Michael Elkins <me@sigpipe.org>'" > .usermap
	@echo "melkins:'Michael Elkins <me@sigpipe.org>'" >> .usermap
	@echo "nboullis:'Nicolas Boullis <nboullis@users.sf.net>'" >> .usermap
	@echo "ossi:'Oswald Buddenhagen <ossi@users.sf.net>'" >> .usermap
	@echo "tytso:'Theodore Ts'o <tytso@users.sf.net>'" >> .usermap
	cvs2cl -U .usermap --no-wrap --separate-header
	@rm -f .usermap ChangeLog.bak

deb:
	CFLAGS="-O2 -mcpu=i686" fakeroot debian/rules binary

deb-clean:
	dh_clean -Xsrc/
	fakeroot debian/rules unpatch

distdir distclean: deb-clean

rpm:
	make dist
	cp $(PACKAGE)-$(VERSION).tar.gz /usr/src/rpm/SOURCES
	rpm -ba --clean isync.spec
