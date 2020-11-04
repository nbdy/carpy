## carpi (obsolete, use [carpi](https://github.com/nbdy/carpi)) 

### why?
my ford fiesta mk6 has an empty slot, which i broke the cover of.<br>
i also wanted an programmable device in my car.<br>
almost nothing on the market fits a 130x30mm slot.<br>
a linux system w/ custom ui/case seemed like the best solution.<br>

### hardware:
- 7" display<br>
- raspberry pi 4<br>
- hdmi ribbon cable (50cm) (one L and one I connector)


### features:
done:
- modular system

todo:
- ui
- gps
- wifi
- bluetooth
- navigation
- musicplayer
- videoplayer
- voicecontrol

#### how to...
##### install dependencies
```
./setup.sh
```

### faq:
Q: where can i find a case for this?<br>
A: over [here](https://github.com/nbdy/cadpi)<br>
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
