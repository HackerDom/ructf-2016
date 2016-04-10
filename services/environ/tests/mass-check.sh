#!/bin/bash

export WIFICARD=wlan0
errors=0
counter=0
for count in {1..10}; do
for i in {101..122}; do
    echo -ne "team$i\t"
    flag=$(echo flag$i | md5sum | cut -d ' ' -f 1)
    ((counter++))
    A=$(python3.5 environ.checker.py put 172.16.16.$i user$i $flag)
    if [ $? -eq 101 ]; then
        python3.5 environ.checker.py get 172.16.16.$i $A $flag
        if [ $? -eq 101 ]; then
        echo "OK"
        else
        ((errors++))
        fi
    else
    ((errors++))
    fi
done
done

echo "Flags: $errors / $counter"