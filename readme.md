## carpi

### why?
my ford fiesta ja8 has a slot under the radio, which isn't used and i broke the cover.<br>
android radio replacements are mostly for a 2 din cover, which looks really bad.<br>
a linux system with touch and custom ui seemed like the best solution.<br>

### hardware:
- 3,5" gpio display (waveshare/etc.)<br>
- raspberry pi 3<br>
- 12 male/female jumper cables<br>
- hdmi ribbon cable


### features:
done:
- basic ui

todo:
- map / navigation
- audio / radio broadcast 
- wardriving
- ...

### installation:
```
sudo ./dependencies.sh
sudo python3 install.py -i
```

### faq:
Q: after assembly and installation the touchscreen input axis are inverted<br>
A: sudo cp 99-calibration.conf /usr/share/X11/xorg.conf.d/
