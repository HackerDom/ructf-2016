#!/bin/bash
while [ 1 ];
do
    echo " *** UPDATING CHECKERS ONLY *** "
    echo " *** Started at: "`date`
    ./cs-checkers.sh
    echo " *** Finished at: "`date`
    sleep 180
done
