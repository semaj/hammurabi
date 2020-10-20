#!/bin/bash

MODULARIZE=./modularize.sh
SRC_DIR=../prolog
FILES="checks$JOBINDEX.pl certs$JOBINDEX.pl"
CLIENT=$1
OUT=all$JOBINDEX.pl

LUA_EXTS=ext.lua
DTLG=datalog # must be on path

rm -f $OUT

if [ $1 = "chrome" ]; then
    cp template_chrome.pl $OUT
else
    cp template.pl $OUT
fi

for f in $FILES; do
    $MODULARIZE $SRC_DIR/$f >> $OUT
done

echo -e "\nenv:domain(\"$2\").\n$1:verified(cert_0)?" >> $OUT

RAW="${RAW:-/tmp/raw.log}"
ts=$(date +%s%N)

$DTLG -l $LUA_EXTS $OUT
E=$?

if [ $3 = "writetime" ]; then
  echo "DATALOG ELAPSED: $((($(date +%s%N) - $ts)/1000000))" >> $RAW
fi
exit $E
