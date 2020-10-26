#!/usr/bin/env bash

CLIENT=$1
DOMAIN=$2

LUA_EXTS=static/ext.lua
DATALOG=../lib/datalog/datalog
MODULARIZE=./modularize.sh

CHECKS=checks$JOBINDEX.pl
CERTS=certs$JOBINDEX.pl

rm gen/chrome_env.pl 2> /dev/null
if [[ $CLIENT == "chrome" ]]; then
  BROWSER=chrome.pl
  $MODULARIZE static/chrome_env.pl > gen/chrome_env.pl
  BROWSER_ENV=gen/chrome_env.pl
else
  BROWSER=firefox.pl
  BROWSER_ENV=""
fi

GEN_FILES="$CHECKS $CERTS"
for f in $GEN_FILES; do
    $MODULARIZE gen/$f > gen/tmp
    mv gen/tmp gen/$f
done

rm gen/chrome.pl 2> /dev/null
rm gen/firefox.pl 2> /dev/null
STATIC_FILES="$BROWSER env.pl std.pl"
for f in $STATIC_FILES; do
    $MODULARIZE static/$f > gen/$f
done


echo -e "\nenv:domain(\"$DOMAIN\").\n$CLIENT:verified(cert_0)?" > gen/query.pl

start_time=$(date +%s%N)
$DATALOG -l $LUA_EXTS gen/$CHECKS gen/env.pl gen/std.pl gen/$BROWSER gen/$CERTS $BROWSER_ENV gen/query.pl > /dev/null
E=$?
if [[ $3 == "writetime" ]]; then
  echo "Datalog execution time (ms): $((($(date +%s%N) - $start_time)/1000000))"
fi
exit $E
