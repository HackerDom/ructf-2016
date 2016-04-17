#!/usr/bin/perl

for (1..2,4..22) {
    printf <<"END", 200+$_, 200+$_, $_;
auto eth0.%d
iface eth0.%d inet static
    address 10.23.$_.1
    netmask 255.255.255.0

END
}
