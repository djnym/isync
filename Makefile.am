SUBDIRS = src
bin_SCRIPTS = get-cert
EXTRA_DIST = debian isync.spec $(bin_SCRIPTS)

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

dist-hook:
	find $(distdir)/debian \( -name CVS -o -name .cvsignore -o -name .#\*# -o -type l \) -print0 | xargs -0r rm -rf

rpm:
	make dist
	cp $(PACKAGE)-$(VERSION).tar.gz /usr/src/rpm/SOURCES
	CFLAGS="-O2 -mcpu=i686" rpm -ba --clean isync.spec

docdir = $(datadir)/doc/isync
doc_DATA = README TODO NEWS ChangeLog AUTHORS
