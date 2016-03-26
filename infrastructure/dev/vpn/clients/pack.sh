#!/bin/bash

SRC=../ca/keys
TMP=tmp
OUT=out

function pack {
    NAME=$1
    rm -f $TMP/*
    cp client.conf $TMP/ructf2016-$NAME.conf
    cp $SRC/ca.crt    $TMP/ructf2016-ca.crt
    cp $SRC/$NAME.crt $TMP/ructf2016-client.crt
    cp $SRC/$NAME.key $TMP/ructf2016-client.key
    pushd $TMP
    tar czvf ../$OUT/$NAME.tgz *
    popd
}

[ -d $TMP ] || mkdir $TMP
[ -d $OUT ] || mkdir $OUT

for i in {01..30}
do
    pack team$i
    pack dev$i
done

rm -f $TMP/*
rmdir $TMP

