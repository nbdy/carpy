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
- hdmi ribbon cable


### features:
done:
- ui (easily extensible)

todo:
- map / navigation
- audio / radio broadcast 
- wardriving
- ...

### installation (autostart):
```
sudo ./dependencies.sh
sudo python3 install.py -i
```

### uninstall (autostart):
```
sudo python3 install.py -u
```

### faq:
Q: after assembly and installation the touchscreen input axis are incorrect<br>
A: sudo cp stl/{{version}}/99-calibration.conf /usr/share/X11/xorg.conf.d/<br>
<br>
Q: how do i adjust the ui to my needs?
A: check the 'templates/' folder. it includes the stuff that makes up the ui.