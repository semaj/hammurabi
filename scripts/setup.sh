set -e

echo 'PATH="$HOME/.cargo/bin:$PATH"' >> .profile
cd engine
git submodule init
git submodule update
cd lib/datalog
./configure
make
cd ../..
cargo build

