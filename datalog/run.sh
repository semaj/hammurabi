#!/usr/bin/env bash

CLIENT=$1
DOMAIN=$2
ENGINE=swipl

DIR=datalog/job$JOBINDEX
gen_start_time=$(date +%s%N)

STATIC_FILES="$CLIENT.pl ${CLIENT}_env.pl types.pl checks.pl std.pl ev.pl"
for f in $STATIC_FILES; do
  cp datalog/static/$f $DIR/$f
done

echo -e ":- module(env, [domain/1]).\nenv:domain(\"$DOMAIN\")." > $DIR/env.pl
echo "Gen execution time: $((($(date +%s%N) - $gen_start_time)/1000000))ms"

start_time=$(date +%s%N)
$ENGINE -q -s $DIR/$CLIENT.pl -t "$CLIENT:certVerifiedChain(cert_0)."
E=$?
if [[ $3 == "writetime" ]]; then
  echo "Datalog execution time: $((($(date +%s%N) - $start_time)/1000000))ms"
fi
exit $E
