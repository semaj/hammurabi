#!/bin/bash

CLIENT=$1

# WATCH dictates which predicate failures should be visible
WATCH="leafDurationValid|std:isTimeValid"
# filter debug output
./prolog/debug.pl $CLIENT 2>&1 | grep --color=always -E $WATCH
# load the client file and load into REPL
swipl -s ./prolog/static/$CLIENT.pl -g prolog