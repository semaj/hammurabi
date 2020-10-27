set -v
set -e

sudo apt update
sudo apt install -yy automake-1.15 libtool autoconf texinfo
curl https://sh.rustup.rs -sSf | sh -s -- -y
git submodule init
git submodule update
cd lib/datalog
./configure
make
cd ../..
