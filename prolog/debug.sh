#!/usr/bin/env bash

CLIENT=$1
DOMAIN=$2
ENGINE=swipl

CHECKS="timeValid nssNameConstraint revoked chainLength parentNotCA domainMatch aCC leafValidity"
ERR_CODES="10 20 40 50 60 30 70 80"
N_CHECKS=$(echo $CHECKS | wc -w | cut -f1)

DIR=prolog/job$JOBINDEX

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
        END { print "])." }' > $DIR/checks.pl

    echo $CHECKS | tr ' ' '\n' | awk -vi="$DISABLED" '
        i == 0 || NR == i {print $1"CheckEnabled(true)."}
        i < 0 {print $1"CheckEnabled(false)."}
        i > 0  && NR != i {print $1"CheckEnabled(false)."}' >> $DIR/checks.pl


    start_time=$(date +%s%N)
    $ENGINE -q -s $DIR/$CLIENT.pl -t "$CLIENT:certVerifiedChain(cert_0)."
    E=$?
    if [[ $3 == "writetime" ]]; then
        echo "Prolog execution time: $((($(date +%s%N) - $start_time)/1000000))ms"
    fi
    return $E
}

echo -e ":- module(env, [domain/1]).\nenv:domain(\"$DOMAIN\")." > $DIR/env.pl
STATIC_FILES="$CLIENT.pl ${CLIENT}_env.pl types.pl std.pl ev.pl"
for f in $STATIC_FILES; do
  cp prolog/static/$f $DIR/$f
done


# Verify with all checks enabled
verify 0 $1 writetime
if [ $? -eq 0 ]; then
    exit $?
fi

verify -1 $1
if [ $? -ne 0 ]; then
    exit 200
fi


# Something failed.
# Enable each check and see which one
for i in `seq 1 $N_CHECKS`; do
    verify $i $1
    if [ $? -ne 0 ]; then
        # >&2 echo `echo $CHECKS | cut -d" " -f$i`" check failed"
        exit `echo $ERR_CODES | cut -d" " -f$i`
    fi
done

# All known checks pass individiually, some unknown failure
# >&2 echo "Unknown failure after all checks"
exit 2
