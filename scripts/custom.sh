#!/usr/bin/env bash
DATALOG="${3:-test}"
echo $DATALOG

RUST_BACKTRACE=1 SCRIPT=$DATALOG ./target/debug/single $1 $2 --ocsp
