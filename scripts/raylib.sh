#!/bin/bash

sudo apt install -y libx11-dev git build-essential cmake vim xorg-dev

cd /tmp/
git clone https://github.com/raysan5/raylib
cd raylib
mkdir build
cd build
cmake ..
make -j4
sudo make install
cd /tmp/
rm -rf raylib