#!/usr/bin/env bash

DATALOG=lib/datalog/datalog
LUA_EXTS=datalog/static/ext.lua
CHECKS=checks$JOBINDEX.pl
CERTS=certs$JOBINDEX.pl

BROWSER_ENV_FILE=datalog/gen/chrome_env.pl
if [ -f "$BROWSER_ENV_FILE" ]; then
  BROWSER_ENV=datalog/gen/chrome_env.pl
fi

FIREFOX_BROWSER_FILE=datalog/gen/firefox.pl
if [ -f "$FIREFOX_BROWSER_FILE" ]; then
  BROWSER=firefox.pl
fi

CHROME_BROWSER_FILE=datalog/gen/chrome.pl
if [ -f "$CHROME_BROWSER_FILE" ]; then
  BROWSER=chrome.pl
fi

$DATALOG -l $LUA_EXTS datalog/gen/$CHECKS datalog/gen/env.pl datalog/gen/std.pl datalog/gen/$BROWSER datalog/gen/$CERTS $BROWSER_ENV datalog/gen/query.pl
