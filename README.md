This repository contains the prototype ACC engine. The engine is responsible for
parsing certificates, emitting Datalog facts, aggregating those facts with
rules, and executing additional ACCs (as Datalog) to determine certificate
validity.

It's designed almost entirely (as of now) for testing chrome.pl and firefox.pl,
which are Datalog implementations of Chrome and Firefox's TLS certificate
validation logic, respectively.

# Setup

The easiest way to get started is to use the Vagrant box. To do so, you'll need
VirtualBox installed. In this directory, you can then run `vagrant up`, then
`vagrant ssh`. `vagrant up` creates a new virtual machine, installs necessary
dependencies, `vagrant ssh` connects to the box. Then run `cd engine`, then set
everything up with `./scripts/setup.sh`.

Note that `vagrant up` might take a few minutes.

## Without Vagrant

If on a Debian-based system, you can run `scripts/install-dependencies.sh` to
install the necessary dependencies. Note that this will attempt to install
Rust---I recommend looking at that file before running it. If not on Debian,
you'll need to look at that file and install the analogous dependencies.

You can then run `scripts/setup.sh`, which will build the Datalog interpreter
and TLS client.

# Usage

Consider the certificate chain in
`certs/0de156c55d46391bf1081fcb9acb6580ae9f8eb6e79af3206cfe8f9f792c002a.pem`. We
can "attach" Datalog to the leaf certificate by editing
`datalog/static/test.pl`. You can add clauses to the `verified(Cert)` predicate.

You can run these assertions over a certificate chain like so:

`./scripts/custom.sh
0de156c55d46391bf1081fcb9acb6580ae9f8eb6e79af3206cfe8f9f792c002a.pem
jameslarisch.com`. `jameslarisch.com` is the domain you're validating against.

`OK` means the constraints were satisfied, an error means it didn't.

After running, you can examine `datalog/gen/job/certs.pl` to examine the facts
you can operate over. You can also look at the other facts and rules in
`datalog/gen/job/*` (for instance `datalog/gen/job/std.pl` contains some
convenience rules).

For now, the `Cert` in `verified(Cert)` is the leaf certificate. You can also
operate over the parent of the leaf---to see an example of this (and other
complex rules) look at Datalog Firefox and Chrome at `datalog/static/firefox.pl`
and `datalog/static/chrome.pl` respectively.

To validate a certificate through Datalog Firefox, call `scripts/firefox.sh
<path to chain pem file> <hostname to validate against>`. Similarly, you can
call `scripts/chrome.sh` for Datalog Chrome.

If after running one of those scripts you get an unknown error that you wish to
debug, you can edit the Datalog files in `datalog/gen/job`, then call
`scripts/debug.sh` to rerun _only_ the Datalog. Note that any subsequent calls
to `chrome.sh` or `firefox.sh` will overwrite the files in `datalog/gen/job` and
`datalog/gen`, which are to be treated as ephemeral.

# Editing the Source

If you edit the Rust code (which handles certificate parsing, signature
validation, and Datalog generation/execution), you need to `cargo build` to
rebuild.

This creates two executables: `target/debug/single` and `target/debug/scale`.
`single` is what you'll probably need.

If you edit the Datalog interpreter (which you shouldn't need to do) you'll have
to run `make` in `lib/datalog`.

To add host (Lua) rules to the Datalog interpreter, edit `datalog/static/ext.lua`.

# Scale

This section can (probably) be ignored unless you are running experiments for
the ACCs paper.

Running the experiments "at scale" is slightly more involved. After building,
you'll execute `./target/debug/scale <mapping-file> <ints-directory> <out-file>`
where `mapping-file` is in the very unique format, `ints-directory` contains all
intermediates (in PEM format) that correspond to the intermediates in the
`mapping-file`, and `out-file` is where you want to write results.

By default this will run Firefox. If you want to run Chrome, preface your
call with `SCRIPT=chrome`. If you are running multiple instances of engine and
want to be thread-safe, preface each thread's call with `JOBINDEX=<i>` where
`i` is the thread ID (or similar). All of that thread's generated files will live
in `datalog/gen/job$JOBINDEX`. If you are running a single thread and omit
`JOBINDEX` then it defaults to the empty string and your generated files will
live in `datalog/gen/job`. You can debug using `debug.sh` as described above,
which also respects the `JOBINDEX` environment variable.

# Convenience

There's also a handy script called `scripts/fetch-chain.rb`. This scripts takes
the SHA256 hash (with no colons, in all lowercase) as an argument and prints the
full chain in PEM format. You can pipe this to a file and use it with the
Datalog Chrome/Firefox scripts.
