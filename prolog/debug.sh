#!/usr/bin/env bash

CLIENT=$1

# WATCH dictates which predicate failures should be visible
WATCH="std:isCA|std:nameMatchesSAN|leafDurationValid|isTimeValid|notCrlSet|strongSignature|keyUsageValid|extKeyUsageValid|internationalValid|checkKeyCertSign|notCrl|notRevoked|firefoxNameMatches"
# filter debug output
./prolog/debug.pl $CLIENT 2>&1 | grep --color=always -E $WATCH
# load the client file and load into REPL
#swipl -s ./prolog/static/$CLIENT.pl -s ./prolog/job/certs.pl -g prolog
swipl -s ./prolog/static/$CLIENT.pl -s ./prolog/job/certs.pl -g prolog
