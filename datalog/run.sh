#!/usr/bin/env bash

CLIENT=$1
DOMAIN=$2

LUA_EXTS=static/ext.lua
DATALOG=../lib/datalog/datalog
MODULARIZE=./modularize.sh

CHECKS=checks$JOBINDEX.pl
CERTS=certs$JOBINDEX.pl

if [ $CLIENT = "chrome" ]; then
  BROWSER=chrome.pl
  $MODULARIZE static/env_chrome.pl > gen/env_chrome.pl
  BROWSER_ENV=gen/env_chrome.pl
else
  BROWSER=firefox.pl
  BROWSER_ENV=""
fi

GEN_FILES="$CHECKS $CERTS"
for f in $GEN_FILES; do
    $MODULARIZE gen/$f > gen/tmp
    mv gen/tmp gen/$f
done

STATIC_FILES="$BROWSER env.pl std.pl"
for f in $STATIC_FILES; do
    $MODULARIZE static/$f > gen/$f
done


echo -e "\nenv:domain(\"$DOMAIN\").\n$CLIENT:verified(cert_0)?" > gen/query.pl

$DATALOG -l $LUA_EXTS gen/$CHECKS gen/env.pl gen/std.pl gen/$BROWSER gen/$CERTS gen/query.pl
E=$?
echo $E
exit $E

#RAW="${RAW:-/tmp/raw.log}"
#ts=$(date +%s%N)

#$DTLG -l $LUA_EXTS $OUT
#E=$?

#if [ $3 = "writetime" ]; then
  #echo "DATALOG ELAPSED: $((($(date +%s%N) - $ts)/1000000))" >> $RAW
#fi
#exit $E
