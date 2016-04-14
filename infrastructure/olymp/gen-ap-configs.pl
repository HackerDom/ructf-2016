#!/usr/bin/perl
use strict;
$\=$/;

my @KEY  = qw(x8m46dm7ag8u ozot5hg0c1sw vwjtb2xrzbfm 6l8xz5ew8rlw);
my @CHAN = qw(1 6 12 1);

open T, 'config.ap.template' or die;
sysread T, my $template, -s T;
close T;

for my $n (1..4) {
    my $out = $template;
    $out =~ s/%N%/$n/g;
    $out =~ s/%KEY%/$KEY[$n-1]/g;
    $out =~ s/%CHAN%/$CHAN[$n-1]/g;

    my $fname="config.ap$n";

    open F, ">", $fname or die;
    print "Writing to: $fname";
    syswrite F, $out;
    close F;
}
print "Done.";
