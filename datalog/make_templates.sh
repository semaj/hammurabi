#!/usr/bin/env bash

OUT=template_chrome.pl # Chrome template file
rm -f $OUT # Delete old version
for f in env.pl std.pl chrome_env.pl chrome.pl; do
  ./modularize.sh gen/$f >> $OUT; # Modularize each file and append
done

OUT=template_firefox.pl # Firefox template file
rm -f $OUT # Delete old version
for f in env_firefox.pl std.pl firefox.pl; do
  ./modularize.sh gen/$f >> $OUT; # Modularize each file and append
done
