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
gen_start_time=$(date +%s%N)

if [[ $CLIENT == "chrome" ]]; then
  BROWSER=chrome.pl
  BROWSER_SPECIFIC=chrome_env.pl
  GEN_FILES="$CHECKS $CERTS"
  for f in $GEN_FILES; do
    $MODULARIZE gen/$f > $DIR/$f
  done
  STATIC_FILES="$BROWSER_SPECIFIC $BROWSER env.pl std.pl ev.pl"
  ARGS="-l $LUA_EXTS $DIR/$CHECKS $DIR/env.pl $DIR/std.pl $DIR/ev.pl $DIR/$BROWSER $DIR/$CERTS $DIR/$BROWSER_SPECIFIC $DIR/query.pl"
elif [[ $CLIENT == "firefox" ]]; then
  BROWSER=firefox.pl
  BROWSER_SPECIFIC=onecrl.pl
  GEN_FILES="$CHECKS $CERTS"
  STATIC_FILES="$BROWSER_SPECIFIC $BROWSER env.pl std.pl ev.pl"
  ARGS="-l $LUA_EXTS $DIR/$CHECKS $DIR/env.pl $DIR/std.pl $DIR/ev.pl $DIR/$BROWSER $DIR/$CERTS $DIR/$BROWSER_SPECIFIC $DIR/query.pl"
else
  #CLIENT="test"
  BROWSER=$CLIENT.pl
  GEN_FILES="$CERTS"
  STATIC_FILES="$BROWSER std.pl"
  ARGS="-l $LUA_EXTS $DIR/std.pl $DIR/$BROWSER $DIR/$CERTS $DIR/query.pl"
fi

for f in $GEN_FILES; do
  $MODULARIZE gen/$f > $DIR/$f
done

for f in $STATIC_FILES; do
    $MODULARIZE static/$f > $DIR/$f
done


echo -e "\nenv:domain(\"$DOMAIN\").\n$CLIENT:verified(cert_0)?" > $DIR/query.pl
echo "Gen execution time: $((($(date +%s%N) - $gen_start_time)/1000000))ms"

start_time=$(date +%s%N)
$DATALOG $(echo $ARGS) > /dev/null
E=$?
if [[ $3 == "writetime" ]]; then
  echo "Datalog execution time: $((($(date +%s%N) - $start_time)/1000000))ms"
fi
exit $E
