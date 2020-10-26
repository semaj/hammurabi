#!/usr/bin/env bash

DATALOG=lib/datalog/datalog
LUA_EXTS=datalog/static/ext.lua
CHECKS=checks$JOBINDEX.pl
CERTS=certs$JOBINDEX.pl

DIR=datalog/gen/job$JOBINDEX
BROWSER_SPECIFIC=onecrl.pl
if [ -f "$DIR/chrome_env.pl" ]; then
  BROWSER_SPECIFIC=chrome_env.pl
fi

FIREFOX_BROWSER_FILE=$DIR/firefox.pl
if [ -f "$FIREFOX_BROWSER_FILE" ]; then
  BROWSER=firefox.pl
fi

CHROME_BROWSER_FILE=$DIR/chrome.pl
if [ -f "$CHROME_BROWSER_FILE" ]; then
  BROWSER=chrome.pl
fi


$DATALOG -l $LUA_EXTS $DIR/$CHECKS $DIR/env.pl $DIR/std.pl $DIR/$BROWSER $DIR/$CERTS $DIR/$BROWSER_SPECIFIC $DIR/query.pl
