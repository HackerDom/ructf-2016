#!/bin/bash
for pid in `ps aux | grep environ.checker | cut -c 10-15`
do
    kill $pid && echo killed $pid
done
