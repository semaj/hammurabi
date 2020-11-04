#!/usr/bin/env bash

CLIENT=$1
DOMAIN=$2

LUA_EXTS=static/ext.lua
DATALOG=../lib/datalog/datalog
MODULARIZE=./modularize.sh

CHECKS=checks$JOBINDEX.pl
CERTS=certs$JOBINDEX.pl

DIR=gen/job$JOBINDEX
mkdir -p $DIR
rm $DIR/* 2> /dev/null

if [[ $CLIENT == "chrome" ]]; then
  BROWSER=chrome.pl
  BROWSER_SPECIFIC=chrome_env.pl
else
  BROWSER=firefox.pl
  BROWSER_SPECIFIC=onecrl.pl
fi

GEN_FILES="$CHECKS $CERTS"
for f in $GEN_FILES; do
    $MODULARIZE gen/$f > $DIR/$f
done

STATIC_FILES="$BROWSER_SPECIFIC $BROWSER env.pl std.pl ev.pl"
for f in $STATIC_FILES; do
    $MODULARIZE static/$f > $DIR/$f
done


echo -e "\nenv:domain(\"$DOMAIN\").\n$CLIENT:verified(cert_0)?" > $DIR/query.pl

start_time=$(date +%s%N)
$DATALOG -l $LUA_EXTS $DIR/$CHECKS $DIR/env.pl $DIR/std.pl $DIR/ev.pl $DIR/$BROWSER $DIR/$CERTS $DIR/$BROWSER_SPECIFIC $DIR/query.pl > /dev/null
E=$?
if [[ $3 == "writetime" ]]; then
  echo "Datalog execution time (ms): $((($(date +%s%N) - $start_time)/1000000))"
fi
exit $E
