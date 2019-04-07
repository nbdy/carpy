## carpi (obsolete, use [carpi](https://github.com/smthnspcl/carpi)) 

### why?
my ford fiesta ja8 has an empty slot, which i broke the cover of.<br>
i also wanted an programmable device in my car.<br>
almost nothing on the market fits a 130x30mm slot.<br>
a linux system w/ custom ui/case seemed like the best solution.<br>

### hardware:
- 3,5" gpio display (waveshare/etc.)<br>
- raspberry pi 3<br>
- 12 male/female jumper cables<br>
- hdmi ribbon cable (50cm) (one L and one I connector)


### features:
done:
- ui
- map
- audio player
- install script
- basic voice control
- radio broadcast 

todo:
- full voice control
- navigation
- wardriving
- ...
- make use of https://kivy.org/doc/stable/api-kivy.storage.redisstore.html (wardriving)
- and https://kivy.org/doc/stable/api-kivy.uix.progressbar.html
- and https://kivy.org/doc/stable/api-kivy.uix.slider.html (music)

### install (dependencies):
```
sudo python3 install.py --all
```

### install (autostart):
```
python3 install.py -ia
```

### uninstall (autostart):
```
python3 install.py -ua
```

### known issues:
- gattlib compilation fails with 'boost_thread not found'

### faq:
Q: where can i find a case for this?<br>
A: over [here](https://github.com/trig0n/cadpi)<br>
<br>
Q: the input axis are correct, but the screen is still horizontal?<br>
A: add "display_rotate=1" to /boot/config.txt<br>
<br>
Q: how do i adjust the ui to my needs?<br>
A: check the 'templates/' folder. it includes the stuff that makes up the ui.<br>
<br>
Q: my mp3's sound super slowed when played over radio?<br>
A: yah.. idk. convert them to wav's (ffmpeg -i in.mp3 out.wav )<br>
<br>
Q: wtf are those keywords you preset?<br>
A: sry. lisping real hard<br>
Q: idc but how do i fix the shitty speech recognition?<br>
A: use 'keyword_generator.py'<br>
Q: but how do i use that?<br>
A: --help
