SUBDIRS = src
man_MANS = isync.1
EXTRA_DIST = debian isyncrc.sample isync.spec $(man_MANS)

log:
	@perl -p -e "s/^(\\S+)\\s+(\\S.+\\S)\\s+(\\S+)\\s*\$$/\$$1:'\$$2 <\$$3>'\\n/" < ../CVSROOT/accounts > .usermap
	cvs2cl -U .usermap --no-wrap --separate-header -I ChangeLog -I NEWS -I TODO -I debian/
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
