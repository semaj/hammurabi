#!/bin/bash 

# Format for test cases
# [Rule],[Test File],[Expected Result]
# Trailing whitespace after Expected Result is ok
# Make sure to have an extra line at the bottom 
# Do not put a \+ (negation) in front of your rules

# In the Zlint file, make sure to comment out 
# (or delete) your verified rule 

# The following script tests a given Zlint Prolog file 
# with a given set of test cases and outputs whether 
# each test passed or failed
# Usage: ./zlint-test.sh [Test Cases File] [Zlint File]
# ex. ./scripts/zlinttesting/zlint-test.sh test-cases.txt zlint


if [[ ! $# -eq 2 ]]
then
    echo "Usage: ./zlint-test.sh [Test Cases File] [Zlint File]"
    exit 1
fi

test_num=1
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
while IFS=",", read -r rule test_file expected; do
    echo "---------- Test #$test_num ----------"
    echo "Rule being tested: $rule"
    echo "Test Data: $test_file"
    echo "Expected Result: $expected"
    cp prolog/static/$2.pl prolog/static/tmpZlint.pl
    echo "verified(Cert) :-" >> prolog/static/tmpZlint.pl 
    echo "  std:isCert(Cert)," >> prolog/static/tmpZlint.pl
    echo "  $rule(Cert)." >> prolog/static/tmpZlint.pl
    actual=`bash scripts/custom.sh $test_file domain tmpZlint | tail -1`
    rm prolog/static/tmpZlint.pl
    echo "Actual Result: $actual"
    expected=`echo $expected | xargs`
    # troubleshooting
    # echo "'"$actual"'"
    # echo "'"$expected"'"
    if [ "$actual" = "$expected" ]
    then 
        echo -e "${GREEN}Test Passed${NC}"
    else 
        echo -e "${RED}Test Failed${NC}"
    fi
    let "test_num++"
done < scripts/zlinttesting/$1