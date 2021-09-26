set -e

git submodule init
git submodule update
cd lib/prolog
./configure
make
cd ../..
cargo build

