#!/usr/bin/env bash

SCRIPT="${SCRIPT:-firefox}"
DOMAIN=$2

CHECKS="timeValid nssNameConstraint revoked chainLength parentNotCA domainMatch aCC leafValidity"
ERR_CODES="10 20 40 50 60 30 70 80"
N_CHECKS=$(echo $CHECKS | wc -w | cut -f1)
CHECKS_PL=gen/checks$JOBINDEX.pl

function verify {
    # Which check should be enabled
    # 0 means all are enabled
    # -1 means all are disabled
    DISABLED=${1:-0}
    WRITETIME=$3

    # Generate checks.pl file
    echo $CHECKS | tr ' ' '\n' | awk -v total="$N_CHECKS" '
        BEGIN { print ":- module(checks, [" }
        NR < total { print "  " $1 "CheckEnabled/1," }
        NR == total { print "  " $1 "CheckEnabled/1" }
        END { print "])." }' > $CHECKS_PL

    echo $CHECKS | tr ' ' '\n' | awk -vi="$DISABLED" '
        i == 0 || NR == i {print $1"CheckEnabled(true)."}
        i < 0 {print $1"CheckEnabled(false)."}
        i > 0  && NR != i {print $1"CheckEnabled(false)."}' >> $CHECKS_PL

    ./run.sh $SCRIPT $DOMAIN $WRITETIME
    return $?
}

cd datalog

# Verify with all checks enabled
verify 0 $1 writetime
if [ $? -eq 0 ]; then
    exit $?
fi

verify -1 $1
if [ $? -ne 0 ]; then
    echo "Unknown failure"
    exit 200
fi


# Something failed.
# Enable each check and see which one
for i in `seq 1 $N_CHECKS`; do
    verify $i $1
    if [ $? -ne 0 ]; then
        >&2 echo `echo $CHECKS | cut -d" " -f$i`" check failed"
        exit `echo $ERR_CODES | cut -d" " -f$i`
    fi
done

# All known checks pass individiually, some unknown failure
>&2 echo "Unknown failure after all checks"
exit 2
