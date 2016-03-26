#!/bin/bash
for i in `seq 30`
do
    NUM=$(printf "%02d" $i)
    echo "ifconfig-push 10.16.$((100+$i)).2 10.16.$((100+$i)).1" > dev$NUM
    echo "ifconfig-push 10.16.$i.2 10.16.$i.1"                   > team$NUM
done

