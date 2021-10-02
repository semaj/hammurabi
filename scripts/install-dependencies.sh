sudo add-apt-repository ppa:swi-prolog/stable
curl https://sh.rustup.rs -sSf | sh -s -- -y
sudo apt-get update
sudo apt-get install -yy \
  make \
  autoconf \
  libtool \
  texinfo \
  automake-1.15 \
  ruby2.5 \
  swi-prolog

echo 'PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
source ~/.profile
sudo gem install descriptive_statistics


