#!/usr/bin/env bash

# firefox.sh <path to chain file> <hostname to validate against>
RUST_BACKTRACE=1 SCRIPT=test ./target/debug/single $1 $2 --ocsp
