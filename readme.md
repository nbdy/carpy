## carpi

### why?
my ford fiesta ja8 has an empty slot, which i broke the cover of.<br>
i also wanted an programmable device in my car.<br>
almost nothing on the market fits a 130x30mm slot.<br>
a linux system w/ custom ui/case seemed like the best solution.<br>

### hardware:
- 3,5" gpio display (waveshare/etc.)<br>
- raspberry pi 3<br>
- 12 male/female jumper cables<br>
- hdmi ribbon cable (50cm) (both ends are L pieces)


### features:
done:
- ui
- audio player
- install script

todo:
- map / navigation
- radio broadcast 
- wardriving
- ...

### install (dependencies):
```
pip install -r requirements.txt
sudo python3 install.py -id
```

### install (autostart):
```
python3 install.py -ia
```

### uninstall (autostart):
```
python3 install.py -ua
```

### faq:
Q: which stl's should i print?<br>
A: use the folder 'stl/final/'; that's my current setup <br>
<br>
Q: why do keep the folders 'stl/v*'?<br>
A: so i can look back on how bad i was at cad<br> 
<br>
Q: why is there a 99-calibration.conf in 'stl/v1/'?<br>
A: the first version had the screen be horizontal.<br>
turning the screen did't turn the input axis of the touchscreen<br>
copying that file to /usr/share/etc/X11/xorg.conf.d/ would fix this issue<br>
<br>
Q: the input axis are correct, but the screen is still horizontal?<br>
A: add "display_rotate=1" to /boot/config.txt<br>
<br>
Q: how do i adjust the ui to my needs?<br>
A: check the 'templates/' folder. it includes the stuff that makes up the ui.