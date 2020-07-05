#!/bin/bash

sudo apt install -y python3 python3-dev python3-pip libicu-dev libharfbuzz-dev \
                    libboost-filesystem-dev libboost-system-dev libboost-regex-dev \
                    libboost-program-options-dev libxml2-dev libpng-dev libjpeg-dev \
                    libtiff-dev libwebp-dev libproj-dev pkg-config libcairo2-dev \
                    libpq-dev libsqlite3-dev libgdal-dev

cd /tmp/
git clone https://github.com/mapnik/mapnik --branch v3.0.x
git submodule update --init
mkdir build
./configure
make
sudo make install
cd /tmp/
rm -rf mapnik