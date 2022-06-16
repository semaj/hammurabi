This repository contains the prototype ACC engine. The engine is responsible for
parsing certificates, emitting Prolog facts, aggregating those facts with
rules, and executing additional ACCs to determine certificate validity.

It's designed almost entirely (as of now) for testing chrome.pl and firefox.pl,
which are Prolog implementations of Chrome and Firefox's TLS certificate
validation logic, respectively.

# Setup

The easiest way to get started is to use the Vagrant box. To do so, you'll need
VirtualBox installed. In this directory, you can then run `vagrant up`, then
`vagrant ssh`. `vagrant up` creates a new virtual machine, installs necessary
dependencies, `vagrant ssh` connects to the box. After connecting to the Vagrant
box, run `cargo build` to build everything. Then, run `make` in the `prolog`
directory to build policy executables.

Note that `vagrant up` might take a few minutes.

## Without Vagrant

If on a Debian-based system, you can run `scripts/install-dependencies.sh` to
install the necessary dependencies. Note that this will attempt to install
Rust---I recommend looking at that file before running it. If not on Debian,
you'll need to look at that file and install the analogous dependencies. Run
`cargo build` after installing dependencies. Then, run `make` in the `prolog`
directory to build policy executables.

# Usage

Consider the certificate chain in
`certs/141c7a18a5a00ef35ef43f89288f80405b358ea407c2deee933fa7d07a52559f.pem`.
You can execute the Chrome verification logic on this chain like so:

`./target/debug/single chrome
certs/141c7a18a5a00ef35ef43f89288f80405b358ea407c2deee933fa7d07a52559f.pem
hrm.auth.gr`. `hrm.auth.gr` is the domain you're validating against.

`OK` means the constraints were satisfied, an error means they were not.

After running, you can examine `prolog/job/certs.pl` to examine the facts
you can operate over. You can also look at the other facts and rules in
`prolog/job/*` (for instance `prolog/job/std.pl` contains some
convenience rules).

**NOTE: we hardcode the current time as Friday, October 2, 2020 1:53:44 AM GMT.
Look at `prolog/std.pl`, `isTimeValid`.** The above certificate is currently
expired, but is valid if you consider today's date Oct 2 :). You can change the
Unix timestamp in `std.pl`
if you want to check current certificates.

For now, the `Cert` in `verifiedChain(Cert)` is the leaf certificate. You can also
operate over the parent of the leaf---to see an example of this (and other
complex rules) look at Prolog Firefox and Chrome at `prolog/static/firefox.pl`
and `prolog/static/chrome.pl` respectively.

To validate a certificate through Prolog Firefox, call `target/debug/single
<client> <path to chain pem file> <hostname to validate against> [--ocsp]
[--staple]`. The `ocsp` and `staple switches decide wether and OCSP revocation
checking is performed.

If certificate verification fails, you can get a meaningful error message in
most cases by subsequently running `prolog/debug.sh <client> <domain>.` If you
get an unknown error that you wish to debug further, you can edit the Prolog
files in `prolog/job`, and run them manually with `swipl` to check what's going
wrong.

# Editing the Source

If you edit the Rust code (which handles certificate parsing, signature
validation, and Prolog generation/execution), you need to `cargo build` to
rebuild.

This creates two executables: `target/debug/single` and `target/debug/scale`.
`single` is what you'll probably need.

If you edit the Prolog code in `prolog/static`, run `make` in the `prolog`
directory. This will build the executables `firefox` and `chrome` in `prolog/bin`
which the Rust binaries will call as shell commands.

# Scale

This section can (probably) be ignored unless you are running experiments for
the ACCs paper.

Running the experiments "at scale" is slightly more involved. After building,
you'll execute `./target/debug/scale <client> <mapping-file> <ints-directory>
<out-file>` where `client` is either `chrome` or `firefox`,  `mapping-file` is
in the very unique format, `ints-directory` contains all intermediates (in PEM
format) that correspond to the intermediates in the `mapping-file`, and
`out-file` is where you want to write results.

If you are running multiple instances of engine and want to be thread-safe,
preface each thread's call with `JOBINDEX=<i>` where `i` is the thread ID (or
similar). All of that thread's generated files will live in
`prolog/job$JOBINDEX`. If you are running a single thread and omit
`JOBINDEX` then it defaults to the empty string and your generated files will
live in `prolog/job`. You can debug using `debug.sh` as described above,
which also respects the `JOBINDEX` environment variable.

# Convenience

There's also a handy script called `scripts/fetch-chain.rb`. This scripts takes
the SHA256 hash (with no colons, in all lowercase) as an argument and prints the
full chain in PEM format. You can pipe this to a file and use it with the
Prolog Chrome/Firefox scripts.
