#!/bin/bash

for i in {101..122}
do
    echo "    {name => 'team$i', network => '172.16.16.$i/32', host => '172.16.16.$i'},"
done
