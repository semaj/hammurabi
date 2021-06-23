#!/bin/bash 

# Format for test cases
# [Rule],[Test File],[Expected Result]
# Make sure to not have any trailing whitespace 
# and to have an extra line at the bottom 
# Do not put a \+ (negation) in front of your rules

# In the Zlint file, make sure to comment out 
# (or delete) your verified rule 

# The following script tests a given Zlint Datalog file 
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
    cp ~/engine/datalog/static/$2.pl ~/engine/datalog/static/tmpZlint.pl
    echo "verified(Cert) :-" >> ~/engine/datalog/static/tmpZlint.pl 
    echo "  std:isCert(Cert)," >> ~/engine/datalog/static/tmpZlint.pl
    echo "  $rule(Cert)." >> ~/engine/datalog/static/tmpZlint.pl
    actual=`bash ~/engine/scripts/custom.sh ~/engine/$test_file domain tmpZlint | tail -1`
    rm ~/engine/datalog/static/tmpZlint.pl
    echo "Actual Result: $actual" 
    if [ "$actual" = "$expected" ]
    then 
        echo -e "${GREEN}Test Passed${NC}"
    else 
        echo -e "${RED}Test Failed${NC}"
    fi
    let "test_num++"
done < ~/engine/scripts/zlinttesting/$1