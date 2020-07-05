#!/bin/bash

sudo apt install -y libtool libbz2-dev

cd /tmp/
wget https://download.savannah.gnu.org/releases/freetype/freetype-2.9.tar.gz
tar xf freetype-2.9.tar.gz
rm freetype-2.9.tar.gz
cd freetype-2.9
./autogen.sh
./configure
make -j4
cd /tmp/
rm -rf freetype-2.9