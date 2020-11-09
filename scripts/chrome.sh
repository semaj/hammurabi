#!/usr/bin/env bash

# chrome.sh <path to chain file> <hostname to validate against>
RUST_BACKTRACE=1 SCRIPT=chrome ./target/debug/single $1 $2 $3
