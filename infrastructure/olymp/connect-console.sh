#!/bin/sh
DEV=/dev/ttyUSB0

if [ ! -c $DEV ]
then
    echo Error: device "$DEV" does not exist
    exit 1
fi

minicom -b 9600 -D $DEV

