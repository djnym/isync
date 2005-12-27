#! /usr/bin/perl -w

use strict;
use File::Path;

-d "tmp" or mkdir "tmp";
chdir "tmp" or die "Cannot enter temp direcory.\n";

sub show($$@);
sub test($$);

################################################################################

# generic syncing tests
my @x01 = (
 [ 8,
   1, 1, "F", 2, 2, "", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "F", 7, 7, "FT", 9, 0, "" ],
 [ 8,
   1, 1, "", 2, 2, "F", 3, 3, "F", 4, 4, "", 5, 5, "", 7, 7, "", 8, 8, "", 10, 0, "" ],
 [ 8, 0, 0,
   1, 1, "", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "", 6, 6, "", 7, 7, "", 8, 8, "" ],
);

#show("01", "01", "", "", "");
my @X01 = (
 [ "", "", "" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "FT", 7, 7, "FT", 9, 9, "", 10, 10, "" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 7, 7, "FT", 8, 8, "T", 9, 10, "", 10, 9, "" ],
 [ 9, 0, 9,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 0, "", 7, 7, "FT", 0, 8, "", 10, 9, "", 9, 10, "" ],
);
test(\@x01, \@X01);

#show("01", "02", "", "", "Expunge Both\n");
my @X02 = (
 [ "", "", "Expunge Both\n" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 9, 9, "", 10, 10, "" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 9, 10, "", 10, 9, "" ],
 [ 9, 0, 9,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 10, 9, "", 9, 10, "" ],
);
test(\@x01, \@X02);

#show("01", "03", "", "", "Expunge Slave\n");
my @X03 = (
 [ "", "", "Expunge Slave\n" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "FT", 7, 7, "FT", 9, 9, "", 10, 10, "" ],
 [ 10,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 9, 10, "", 10, 9, "" ],
 [ 9, 0, 9,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 0, "", 7, 7, "FT", 10, 9, "", 9, 10, "" ],
);
test(\@x01, \@X03);

#show("01", "04", "", "", "Sync Pull\n");
my @X04 = (
 [ "", "", "Sync Pull\n" ],
 [ 9,
   1, 1, "F", 2, 2, "", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "F", 7, 7, "FT", 9, 9, "" ],
 [ 9,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 7, 7, "FT", 8, 8, "T", 9, 9, "", 10, 0, "" ],
 [ 9, 0, 0,
   1, 1, "F", 2, 2, "", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "", 7, 7, "FT", 0, 8, "", 9, 9, "" ],
);
test(\@x01, \@X04);

#show("01", "05", "", "", "Sync Flags\n");
my @X05 = (
 [ "", "", "Sync Flags\n" ],
 [ 8,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "F", 7, 7, "FT", 9, 0, "" ],
 [ 8,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 7, 7, "FT", 8, 8, "", 10, 0, "" ],
 [ 8, 0, 0,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "", 7, 7, "FT", 8, 8, "" ],
);
test(\@x01, \@X05);

#show("01", "06", "", "", "Sync Delete\n");
my @X06 = (
 [ "", "", "Sync Delete\n" ],
 [ 8,
   1, 1, "F", 2, 2, "", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "FT", 7, 7, "FT", 9, 0, "" ],
 [ 8,
   1, 1, "", 2, 2, "F", 3, 3, "F", 4, 4, "", 5, 5, "", 7, 7, "", 8, 8, "T", 10, 0, "" ],
 [ 8, 0, 0,
   1, 1, "", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "", 6, 0, "", 7, 7, "", 0, 8, "" ],
);
test(\@x01, \@X06);

#show("01", "07", "", "", "Sync New\n");
my @X07 = (
 [ "", "", "Sync New\n" ],
 [ 10,
   1, 1, "F", 2, 2, "", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "F", 7, 7, "FT", 9, 9, "", 10, 10, "" ],
 [ 10,
   1, 1, "", 2, 2, "F", 3, 3, "F", 4, 4, "", 5, 5, "", 7, 7, "", 8, 8, "", 9, 10, "", 10, 9, "" ],
 [ 9, 0, 9,
   1, 1, "", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "", 6, 6, "", 7, 7, "", 8, 8, "", 10, 9, "", 9, 10, "" ],
);
test(\@x01, \@X07);

#show("01", "08", "", "", "Sync PushFlags PullDelete\n");
my @X08 = (
 [ "", "", "Sync PushFlags PullDelete\n" ],
 [ 8,
   1, 1, "F", 2, 2, "F", 3, 3, "FS", 4, 4, "", 5, 5, "T", 6, 6, "F", 7, 7, "FT", 9, 0, "" ],
 [ 8,
   1, 1, "", 2, 2, "F", 3, 3, "F", 4, 4, "", 5, 5, "", 7, 7, "", 8, 8, "T", 10, 0, "" ],
 [ 8, 0, 0,
   1, 1, "", 2, 2, "F", 3, 3, "F", 4, 4, "", 5, 5, "", 6, 6, "", 7, 7, "", 0, 8, "" ],
);
test(\@x01, \@X08);

# size restriction tests

my @x10 = (
 [ 0,
   1, 0, "", 2, 0, "*" ],
 [ 0,
   3, 0, "*" ],
 [ 0, 0, 0,
    ],
);

#show("10", "11", "MaxSize 1k\n", "MaxSize 1k\n", "");
my @X11 = (
 [ "MaxSize 1k\n", "MaxSize 1k\n", "" ],
 [ 2,
   1, 1, "", 2, 2, "*" ],
 [ 2,
   3, 1, "*", 1, 2, "" ],
 [ 2, 0, 1,
   -1, 1, "", 1, 2, "", 2, -1, "" ],
);
test(\@x10, \@X11);

my @x20 = @X11[1,2,3];

#show("20", "11", "MaxSize 1k\n", "MaxSize 1k\n", ""); # sic! - 11
test(\@x20, \@X11);

#show("20", "22", "", "MaxSize 1k\n", "");
my @X22 = (
 [ "", "MaxSize 1k\n", "" ],
 [ 3,
   1, 1, "", 2, 2, "*", 3, 3, "*" ],
 [ 2,
   3, 1, "*", 1, 2, "" ],
 [ 2, 0, 1,
   3, 1, "", 1, 2, "", 2, -1, "" ],
);
test(\@x20, \@X22);

# expiration tests

my @x30 = (
 [ 0,
   1, 0, "F", 2, 0, "", 3, 0, "", 4, 0, "", 5, 0, "" ],
 [ 0,
   ],
 [ 0, 0, 0,
    ],
);

#show("30", "31", "", "", "MaxMessages 3\n");
my @X31 = (
 [ "", "", "MaxMessages 3\n" ],
 [ 5,
   1, 1, "F", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5,
   1, 1, "F", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5, 0, 0,
   1, 1, "F", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "" ],
);
test(\@x30, \@X31);

my @x40 = @X31[1,2,3];

#show("40", "41", "", "", "MaxMessages 3\nExpunge Both\n");
my @X41 = (
 [ "", "", "MaxMessages 3\nExpunge Both\n" ],
 [ 5,
   1, 1, "F", 2, 2, "", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5,
   1, 1, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5, 2, 0,
   1, 1, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
);
test(\@x40, \@X41);

my @x50 = (
 [ 5,
   1, 1, "F", 2, 2, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5,
   1, 1, " ", 2, 2, "T", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5, 2, 0,
   1, 1, "F", 2, 2, "X", 3, 3, "", 4, 4, "", 5, 5, "" ],
);

#show("50", "51", "", "", "MaxMessages 3\nExpunge Both\n");
my @X51 = (
 [ "", "", "MaxMessages 3\nExpunge Both\n" ],
 [ 5,
   1, 1, "", 2, 2, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5,
   2, 2, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
 [ 5, 2, 0,
   2, 2, "F", 3, 3, "", 4, 4, "", 5, 5, "" ],
);
test(\@x50, \@X51);


################################################################################

chdir "..";
rmdir "tmp";
print "OK.\n";
exit 0;


sub fcfg(@)
{
	return join(" // ", map({ my $t = $_; chomp $t; $t =~ s/\n/ \/ /g; $t; } @_));
}

sub qm($)
{
	shift;
	s/\\/\\\\/g;
	s/\"/\\"/g;
	s/\"/\\"/g;
	s/\n/\\n/g;
	return $_;
}

# $global, $master, $slave, $channel
sub runsync($$$)
{
	open(FILE, ">", ".mbsyncrc") or
		die "Cannot open .mbsyncrc.\n";
	print FILE
"MaildirStore master
Path ./
Inbox ./master
".shift()."
MaildirStore slave
Path ./
Inbox ./slave
".shift()."
Channel test
Master :master:
Slave :slave:
SyncState *
".shift();
	close FILE;
	system "../mbsync -q -c .mbsyncrc test";
	unlink ".mbsyncrc";
}

# $path
sub readbox($)
{
	my $bn = shift;

	(-d $bn) or
		die "No mailbox '$bn'.\n";
	(-d $bn."/tmp" and -d $bn."/new" and -d $bn."/cur") or
		die "Invalid mailbox '$bn'.\n";
	open(FILE, "<", $bn."/.uidvalidity") or die "Cannot read UID validity of mailbox '$bn'.\n";
	my $dummy = <FILE>;
	chomp(my $mu = <FILE>);
	close FILE;
	my %ms = ();
	for my $d ("cur", "new") {
		opendir(DIR, $bn."/".$d) or next;
		for my $f (grep(!/^\.\.?$/, readdir(DIR))) {
			my ($uid, $flg, $num);
			if ($f =~ /^\d+\.\d+_\d+\.[-[:alnum:]]+,U=(\d+):2,(.*)$/) {
				($uid, $flg) = ($1, $2);
			} elsif ($f =~ /^\d+\.\d+_(\d+)\.[-[:alnum:]]+:2,(.*)$/) {
				($uid, $flg) = (0, $2);
			} else {
				print STDERR "unrecognided file name '$f' in '$bn'.\n";
				exit 1;
			}
			open(FILE, "<", $bn."/".$d."/".$f) or die "Cannot read message '$f' in '$bn'.\n";
			my $sz = 0;
			while (<FILE>) {
				/^Subject: (\d+)$/ && ($num = $1);
				$sz += length($_);
			}
			close FILE;
			if (!defined($num)) {
				print STDERR "message '$f' in '$bn' has no identifier.\n";
				exit 1;
			}
			@{ $ms{$num} } = ($uid, $flg.($sz>1000?"*":""));
		}
	}
	return ($mu, %ms);
}

# $boxname
sub showbox($)
{
	my ($bn) = @_;

	my ($mu, %ms) = readbox($bn);
	print " [ $mu,\n   ";
	my $frst = 1;
	for my $num (sort {my ($ca, $cb) = ($ms{$a}[0], $ms{$b}[0]); ($ca?$ca:$a+1000) <=> ($cb?$cb:$b+1000)} keys %ms) {
		if ($frst) {
			$frst = 0;
		} else {
			print ", ";
		}
		print "$num, $ms{$num}[0], \"$ms{$num}[1]\"";
	}
	print " ],\n";
}

# $num
sub showchan()
{
	showbox("master");
	showbox("slave");
	open(FILE, "<", "slave/.mbsyncstate") or
		die "Cannot read sync state.\n";
	$_ = <FILE>;
	/^1:(\d+) 1:(\d+):(\d+)\n$/;
	print " [ $1, $2, $3,\n   ";
	my $frst = 1;
	for (<FILE>) {
		if (!/^(-?\d+) (-?\d+) (.*)\n$/) {
			print STDERR "Malformed sync state entry '$_'.\n";
			next;
		}
		if ($frst) {
			$frst = 0;
		} else {
			print ", ";
		}
		print "$1, $2, \"$3\"";
	}
	print " ],\n";
	close FILE;
}

sub show($$@)
{
	my ($sx, $tx, @sfx) = @_;
	my @sp;
	eval "\@sp = \@x$sx";
	mkchan($sp[0], $sp[1], @{ $sp[2] });
	print "my \@x$sx = (\n";
	showchan();
	print ");\n";
	&runsync(@sfx);
	print "my \@X$tx = (\n";
	print " [ ".join(", ", map('"'.qm($_).'"', @sfx))." ],\n";
	showchan();
	print ");\n";
	print "test(\\\@x$sx, \\\@X$tx);\n\n";
	rmtree "slave";
	rmtree "master";
}

# $boxname, $maxuid, @msgs
sub mkbox($$@)
{
	my ($bn, $mu, @ms) = @_;

	rmtree($bn);
	(mkdir($bn) and mkdir($bn."/tmp") and mkdir($bn."/new") and mkdir($bn."/cur")) or
		die "Cannot create mailbox $bn.\n";
	open(FILE, ">", $bn."/.uidvalidity") or die "Cannot create UID validity for mailbox $bn.\n";
	print FILE "1\n$mu\n";
	close FILE;
	while (@ms) {
		my ($num, $uid, $flg) = (shift @ms, shift @ms, shift @ms);
		if ($uid) {
			$uid = ",U=".$uid;
		} else {
			$uid = "";
		}
		my $big = $flg =~ s/\*//;
		open(FILE, ">", $bn."/cur/0.1_".$num.".local".$uid.":2,".$flg) or
			die "Cannot create message $num in mailbox $bn.\n";
		print FILE "From: foo\nTo: bar\nDate: Thu, 1 Jan 1970 00:00:00 +0000\nSubject: $num\n\n".(("A"x50)."\n")x($big*30);
		close FILE;
	}
}

# \@master, \@slave, @syncstate
sub mkchan($$@)
{
	my ($m, $s, @t) = @_;
	&mkbox("master", @{ $m });
	&mkbox("slave", @{ $s });
	open(FILE, ">", "slave/.mbsyncstate") or
		die "Cannot create sync state.\n";
	print FILE "1:".shift(@t)." 1:".shift(@t).":".shift(@t)."\n";
	while (@t) {
		print FILE shift(@t)." ".shift(@t)." ".shift(@t)."\n";
	}
	close FILE;
}

# $config, $boxname, $maxuid, @msgs
sub ckbox($$$@)
{
	my ($bn, $MU, @MS) = @_;

	my ($mu, %ms) = readbox($bn);
	if ($mu != $MU) {
		print STDERR "MAXUID mismatch for '$bn'.\n";
		return 1;
	}
	while (@MS) {
		my ($num, $uid, $flg) = (shift @MS, shift @MS, shift @MS);
		if (!defined $ms{$num}) {
			print STDERR "No message $bn:$num.\n";
			return 1;
		}
		if ($ms{$num}[0] ne $uid) {
			print STDERR "UID mismatch for $bn:$num.\n";
			return 1;
		}
		if ($ms{$num}[1] ne $flg) {
			print STDERR "Flag mismatch for $bn:$num.\n";
			return 1;
		}
		delete $ms{$num};
	}
	if (%ms) {
		print STDERR "Excess messages in '$bn': ".join(", ", sort({$a <=> $b } keys(%ms))).".\n";
		return 1;
	}
	return 0;
}

# $config, \@master, \@slave, @syncstate
sub ckchan($$$@)
{
	my ($cfg, $M, $S, @T) = @_;
	my $rslt = 0;
	open(FILE, "<", "slave/.mbsyncstate") or
		die "Cannot read sync state.\n";
	chomp(my $l = <FILE>);
	chomp(my @ls = <FILE>);
	close FILE;
	my $xl = "1:".shift(@T)." 1:".shift(@T).":".shift(@T);
	if ($l ne $xl) {
		print STDERR "Sync state header mismatch: '$l' instead of '$xl'.\n";
		$rslt = 1;
	} else {
		for $l (@ls) {
			$xl = shift(@T)." ".shift(@T)." ".shift(@T);
			if ($l ne $xl) {
				print STDERR "Sync state entry mismatch: '$l' instead of '$xl'.\n";
				$rslt = 1;
				last;
			}
		}
	}
	$rslt |= &ckbox("master", @{ $M });
	$rslt |= &ckbox("slave", @{ $S });
	return $rslt;
}

sub printbox($$@)
{
	my ($bn, $mu, @ms) = @_;

	print " [ $mu,\n   ";
	my $frst = 1;
	while (@ms) {
		if ($frst) {
			$frst = 0;
		} else {
			print ", ";
		}
		print shift(@ms).", ".shift(@ms).", \"".shift(@ms)."\"";
	}
	print " ],\n";
}

sub printchan($$@)
{
	my ($m, $s, @t) = @_;

	&printbox("master", @{ $m });
	&printbox("slave", @{ $s });
	print " [ ".shift(@t).", ".shift(@t).", ".shift(@t).",\n   ";
	my $frst = 1;
	while (@t) {
		if ($frst) {
			$frst = 0;
		} else {
			print ", ";
		}
		print shift(@t).", ".shift(@t).", \"".shift(@t)."\"";
	}
	print " ],\n";
	close FILE;
}

sub test($$)
{
	my ($sx, $tx) = @_;

	mkchan($$sx[0], $$sx[1], @{ $$sx[2] });
	&runsync(@{ $$tx[0] });
	if (ckchan(fcfg(@{ $$tx[0] }), $$tx[1], $$tx[2], @{ $$tx[3] })) {
		print "Input:\n";
		printchan($$sx[0], $$sx[1], @{ $$sx[2] });
		print "Options:\n";
		print " [ ".join(", ", map('"'.qm($_).'"', @{ $$tx[0] }))." ],\n";
		print "Expected result:\n";
		printchan($$tx[1], $$tx[2], @{ $$tx[3] });
		print "Actual result:\n";
		showchan();
		exit 1;
	}
	rmtree "slave";
	rmtree "master";
}
