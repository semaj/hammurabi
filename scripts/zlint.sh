#!/bin/bash

# The following rudimentry code runs a series of lints using the zlint file 
# in prolog/gen/job/zlint.pl (emulates zlint)
# *Note that the file can be changed in the while loop

# The code queries each lint in prolog/static/applies_rules.txt 
# The apply rule and lint rule are seperated by a ";" with the 
# applies rule coming first 
# If a rule doesnt apply, it will just return "NA"
# I had to "invert" some of my rules in the zlint file so 
# that they are true when the certificate is correct 

# Usage: ./scripts/zlint.sh testdata/caValCountry.pem | jq
# *The jq is used to format the output

./target/debug/single chrome $1 foo.com --ocsp > /dev/null
./prolog/zlint/driver.py prolog/zlint/zlint.pl prolog/zlint/applies_rules.txt