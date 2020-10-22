This repository contains the prototype ACC engine. The engine is responsible for
parsing certificates, emitting Datalog facts, aggregating those facts with
rules, and executing the Datalog interpreter to determine whether the Datalog
deems the certificate valid.

It's designed almost entirely (as of now) for testing chrome.pl and firefox.pl,
which are Datalog implementations of Chrome and Firefox's TLS certificate
validation logic, respectively.

# Getting Started

First, run `git submodule init && git submodule update` to ensure the Datalog
submodule is initialized.

Then build Datalog. `cd lib/datalog && ./configure && make`. Note that you'll
need the following dependencies: `libtool autoconf automake-1.15 texinfo`.

From this point forward, everything should be executed from the root directory
of this repository. To build, `cargo build`. This creates two executables:
`target/debug/single` and `target/debug/scale`. `single` is what you'll probably
need.

To validate a certificate through Datalog Firefox, call `scripts/firefox.sh
<path to chain pem file> <hostname to validate against>`. Similarly, you can
call `scripts/chrome.sh` for Datalog Chrome.

If after running one of those scripts you get an unknown error that you wish to
debug, you can edit the Datalog files in `datalog/gen/`, then call
`scripts/debug.sh` to rerun _only_ the Datalog. Note that any subsequent calls
to `chrome.sh` or `firefox.sh` will overwrite the files in `datalog/gen`, which
are to be treated as ephemeral.

# Convenience

There's also a handy script called `scripts/fetch-chain.rb`. This scripts takes
the SHA256 hash (with no colons, in all lowercase) as an argument and prints the
full chain in PEM format. You can pipe this to a file and use it with the
Datalog Chrome/Firefox scripts.
