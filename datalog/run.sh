#!/bin/bash

MODULARIZE=./modularize.sh
FILES="checks$JOBINDEX.pl certs$JOBINDEX.pl"
CLIENT=$1
OUT=gen/all$JOBINDEX.pl

LUA_EXTS=static/ext.lua
DTLG=datalog # must be on path

rm -f $OUT

if [ $CLIENT = "chrome" ]; then
    cp template_chrome.pl $OUT
else
    cp template_firefox.pl $OUT
fi

for f in $FILES; do
    $MODULARIZE static/$f >> $OUT
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
