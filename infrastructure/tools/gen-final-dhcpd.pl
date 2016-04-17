#!/usr/bin/perl

for (1..2,4..22) {
    print <<"END";
subnet 10.23.$_.0 netmask 255.255.255.0 {
        option routers 10.23.$_.1;
        pool {
                allow members of "vulnbox";
                range 10.23.$_.2 10.23.$_.2;
        }

        pool {
                deny members of "vulnbox";
                range 10.23.$_.129 10.23.$_.200;
        }
}
END
}
