#!/usr/bin/perl
use strict;
$\=$/;

open OUT, ">", "dhcpd.conf.olymp" or die;
select OUT;

print <<"HEAD";
ddns-update-style none;

option domain-name "ructf.org";
option domain-name-servers 8.8.8.8, 8.8.4.4;

default-lease-time 600;
max-lease-time 3600;

authoritative;

log-facility local7;
HEAD

print_subnet($_) for 11..14;    # OLYMP-* Wi-Fi networks
print_subnet($_) for 101..199;  # Ethernet networks

close OUT;

sub print_subnet {
    my $n = shift;
    print "subnet 10.0.$n.0 netmask 255.255.255.0 { range 10.0.$n.100 10.0.$n.199; option routers 10.0.$n.1; }";
}
