#!/usr/bin/env bash

# firefox.sh <path to chain file> <hostname to validate against>
RUST_BACKTRACE=1 SCRIPT=firefox ./target/debug/single $1 $2
