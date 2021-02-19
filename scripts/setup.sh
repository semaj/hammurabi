set -e

git submodule init
git submodule update
cd lib/datalog
./configure
make
cd ../..
cargo build

