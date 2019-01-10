#!/usr/bin/env bash

sudo apt install python3 python3-dev python3-pip gpsd gpsd-clients libjpeg-dev libtiff-dev xserver-xorg-input-evdev libsndfile-dev tcpdump -y
sudo pip3 install -r requirements.txt
sudo cp stl/final/99-calibration.conf /usr/share/X11/xorg.conf.d/
echo "display_rotate=1" | sudo tee -a /boot/config.txt
cd /opt/
git clone https://github.com/ChristopheJacquet/PiFmRds
cd PiFmRds/src/
make clean
make
cd /tmp/
wget http://osoyoo.com/driver/LCD_show_35hdmi.tar.gz
tar xf LCD_show_35hdmi.tar.gz
rm LCD_show_35hdmi.tar.gz
cd LCD_show_35hdmi/
sudo ./LCD35_480\*320