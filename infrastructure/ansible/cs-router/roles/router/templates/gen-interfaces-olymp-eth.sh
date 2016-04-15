#!/bin/bash

OUTFILE=interfaces.olymp.eth-teams
> $OUTFILE
for i in {101..199}
do
    echo "auto eth0.$i"                >> $OUTFILE
    echo "iface eth0.$i inet static"   >> $OUTFILE
    echo "    address 10.0.$i.1"       >> $OUTFILE
    echo "    netmask 255.255.255.0"   >> $OUTFILE
    echo                               >> $OUTFILE
done
echo "Done: $OUTFILE"
