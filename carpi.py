from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname, isfile, isdir, expanduser
from os import listdir, geteuid, makedirs, environ
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from subprocess import Popen, PIPE
from random import randint
from pyaudio import PyAudio, paInt16, paContinue
from datetime import datetime
import struct

from kivy.app import App
from kivy.config import Config
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from kivy.core.audio import SoundLoader
from kivy.properties import StringProperty

environ["SDL_FBDEV"] = "/dev/fb0"

RUNNING_PATH = dirname(abspath(__file__)) + "/"

if not isdir(RUNNING_PATH + "log/"):
    makedirs(RUNNING_PATH + "log/")

log.add(RUNNING_PATH + "log/output.log", enqueue=True, backtrace=True)

Config.set("kivy", "log_enable", 1)
Config.set("kivy", "log_level", "debug")
Config.set("kivy", "log_dir", RUNNING_PATH + "log/")

# todo
# overview wifi
# - is connected
# -- signal strength
# wireless
# - wifi list / scan option
# - bluetooth list / scan option
# -- device view / options
# settings
# - overview
# -- design
# - wifi
# - bluetooth
# -- ctrl state
# -- wardrive mode
# todo map: https://github.com/kivy-garden/garden.mapview
# todo geocoder for map
# todo virtual keyboard: https://kivy.org/doc/stable/api-kivy.uix.vkeyboard.html


class Bluetooth(object):
    @staticmethod
    def get_bluetooth_device():
        for f in listdir("/dev/"):
            if f.startswith("hci"):
                return f
        return None

    @staticmethod
    def get_bluetooth_status_string():
        dev = Bluetooth.get_bluetooth_device()
        if dev is None:
            return "no bluetooth device"
        return dev


class Network(Thread):
    daemon = True
    do_run = False

    sleep_time = 2
    callback = None

    last_ip_dict = None

    def __init__(self, callback):
        Thread.__init__(self)
        self.callback = callback
        self.do_run = True

    @staticmethod
    def get_available_interfaces():
        av_ifaces = []
        for iface in netifaces.interfaces():
            for prefix in ['e', 'wl']:
                if iface.startswith(prefix):
                    av_ifaces.append(iface)
        return av_ifaces

    def check_has_ip(self):
        dct = {}
        for iface in self.get_available_interfaces():
            dct[iface] = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
        return dct

    def run(self):
        while self.do_run:
            ip_dct = self.check_has_ip()
            if self.last_ip_dict != ip_dct:
                self.last_ip_dict = ip_dct
                self.callback(ip_dct)
            sleep(self.sleep_time)

    def stop(self):
        self.do_run = False


class GPS(Thread):
    daemon = True
    do_run = False

    sleep_time = 2
    callback = None

    current_position = None

    def __init__(self, callback):
        log.debug("initializing gps")
        Thread.__init__(self)
        log.debug("registering callback")
        self.callback = callback
        try:
            self.client = gps(mode=WATCH_ENABLE)
            self.do_run = True
        except OSError:
            log.exception("could not connect to gpsd")

        log.debug("initialized gps")

    def parse_current_position(self):
        c = self.client
        self.current_position = {
            "longitude": c.fix.longitude,
            "latitude": c.fix.latitude,
            "altitude": c.fix.altitude,
            "speed": c.fix.speed,
            "climb": c.fix.climb,
            "satellites_used": c.satellites_used,
            "precision": 0,
            "status": "tracking"
        }
        if "precision" in c.__dict__.keys():
            self.current_position["precision"] = c.precision
        else:
            self.current_position["status"] = "not found"

    def run(self):
        log.debug("running")
        while self.do_run:
            self.client.next()
            if self.client.fix != self.current_position:
                self.parse_current_position()
                self.callback(self.current_position)
            sleep(self.sleep_time)

    def stop(self):
        self.do_run = False


class WiFi(Thread):
    daemon = True
    do_run = False

    callback = None
    interface = None

    def __init__(self, callback):
        Thread.__init__(self)
        log.debug("initializing wifi")
        self.callback = callback
        self.do_run = True
        log.debug("initialized wifi")
        if not Static.is_root():
            log.warning("not root, disabling wifi")
            self.do_run = False
        if self.interface is None:
            log.warning("no interface, disabling wifi")
            self.do_run = False

    def _scapy_cb(self, pkt):
        if pkt.haslayer(Dot11):
            pass

    def _scapy_stop_filter(self, pkt):
        return not self.do_run

    def run(self):
        if self.do_run:
            sniff(iface=self.interface, lfilter=self._scapy_cb, stop_filter=self._scapy_stop_filter)

    def stop(self):
        self.do_run = False


class Static(object):
    @staticmethod
    def append_slash(data):
        if not data.endswith("/"):
            data += "/"
        return data

    @staticmethod
    def is_root():
        return geteuid() == 0

    @staticmethod
    def is_pi():
        return isfile("/proc/device-tree/model")


# todo: support nested albums
class AudioLibrary(object):
    songs = []
    path = None

    @staticmethod
    def get_songs_in_dir(directory):
        directory = Static.append_slash(directory)
        songs = []
        for fp in listdir(directory):
            if fp.endswith(".mp3") or fp.endswith(".wav"):
                songs.append(directory + fp)
        return songs

    def __init__(self, path="~/Music/"):
        if path.startswith("~"):
            if Static.is_pi() and Static.is_root():
                self.path = "/home/pi" + path[1:]
            else:
                self.path = expanduser(path)
        else:
            self.path = Static.append_slash(abspath(path))
        self.songs = self.get_songs_in_dir(self.path)
        log.debug("initializing with audio directory '" + self.path + "'")
        log.debug("found " + str(len(self.songs)) + " songs in directory")

    def get_random_song(self):
        return self.songs[randint(0, len(self.songs) - 1)]


class Player(Thread):
    daemon = True
    do_run = False

    playing = False
    queue = []
    current_song = None
    current_song_position = 0

    audio_lib = None

    def __init__(self, audio_lib):
        Thread.__init__(self)
        self.audio_lib = audio_lib
        self.do_run = True

    def play(self, fp):
        pass

    def pause(self):
        pass

    def next(self):
        pass

    def unpause(self):
        pass

    def enqueue(self, fp):
        self.queue.append(fp)

    def enqueue_dir(self, fp):
        self.queue += self.audio_lib.get_songs_in_dir(fp)

    def stop(self):
        pass

    def run(self):
        while self.do_run:
            pass


class FMTransmitter(Player):
    css = None
    freq = 104.2
    enable_radio_text = True
    last_cmd = []
    pi_fm_rds_path = "/opt/PiFmRds/src/pi_fm_rds"

    def __init__(self, audio_lib):
        Player.__init__(self, audio_lib)
        if Static.is_pi():
            if not isfile(self.pi_fm_rds_path):
                raise Exception("/opt/PiFmRds/src/pi_fm_rds does not exist")

    def manufacture_cmd(self, fp):
        cmd = ["./", self.pi_fm_rds_path, "-freq", str(self.freq), "-audio"]
        if fp.endswith(".mp3"):
            cmd = ["sox", "-t", fp, "-t", "wav", "-", "|"] + cmd + ["-"]
        else:
            cmd += fp
        log.debug("manufactured this command:")
        log.debug("\t" + str(cmd))
        return cmd

    def play(self, fp):
        if isfile(fp):
            self.last_cmd = self.manufacture_cmd(fp)
            self.css = Popen(self.last_cmd, stdout=PIPE)
            return True
        else:
            log.error(fp + "does not exist")
            return False

    def pause(self):
        self.css.kill()

    def unpause(self):
        if len(self.last_cmd) > 0:
            self.css = Popen(self.last_cmd, stdout=PIPE)
        else:
            self.play(self.audio_lib.get_random_song())

    def next(self):
        self.css.kill()
        self.play(self.audio_lib.get_random_song())


class AuxOut(Player):
    def play(self, fp):
        self.playing = True
        self.current_song = SoundLoader.load(fp)
        self.current_song.bind(on_stop=self.cb_current_song_ended)
        log.debug("loaded song '" + self.current_song.source + "' with a length of " + str(self.current_song.length))
        self.current_song.play()

    def cb_current_song_ended(self, signal):
        if self.playing:
            log.debug(signal)
            log.debug(self.current_song.source + " has ended; playing next song")
            self.play(self.audio_lib.get_random_song())

    def next(self):
        self.current_song.stop()

    def pause(self):
        self.playing = False
        self.current_song_position = self.current_song.get_pos()
        self.current_song.stop()

    def unpause(self):
        self.playing = True
        if self.current_song is not None:
            if self.current_song.source is not None:
                self.current_song.play()
                self.current_song.seek(self.current_song_position)
        else:
            self.play(self.audio_lib.get_random_song())


audio_library = AudioLibrary()
audio = None


class Audio(Screen):
    pass


class AudioPlayer(Screen):
    audio = None
    current_song = StringProperty()

    def change_to_next_song(self):
        self.audio.next()

    def play_or_pause(self):
        if self.audio.playing:
            self.ids["btn_play_pause"].text = ">"
            self.audio.pause()
            self.audio.playing = False
        else:
            self.ids["btn_play_pause"].text = "||"
            self.audio.unpause()
            self.audio.playing = True


class AudioAux(AudioPlayer):
    def __init__(self):
        Screen.__init__(self, name="audio_aux")
        audio = AuxOut(audio_library)
        self.audio = audio


class AudioFM(AudioPlayer):
    def __init__(self):
        Screen.__init__(self, name="audio_fm")
        audio = FMTransmitter(audio_library)
        self.audio = audio


class Wireless(Screen):
    def __init__(self):
        Screen.__init__(self, name="wireless")


class WirelessWiFi(Screen):
    def __init__(self):
        Screen.__init__(self, name="wireless_wifi")


class WirelessBluetooth(Screen):
    def __init__(self):
        Screen.__init__(self, name="wireless_bluetooth")


class Settings(Screen):
    def __init__(self):
        Screen.__init__(self, name="settings")


class SettingsAudio(Screen):
    def __init__(self):
        Screen.__init__(self, name="settings_audio")


class SettingsWireless(Screen):
    def __init__(self):
        Screen.__init__(self, name="settings_wireless")


class Map(Screen):
    def __init__(self):
        Screen.__init__(self, name="map")


class Overview(Screen):
    network = None

    network_status = StringProperty("disconnected")

    wifi_status = StringProperty("disconnected")
    wifi_essid = StringProperty()
    wifi_ip = StringProperty()

    eth_status = StringProperty("disconnected")
    eth_ip = StringProperty()

    gps = None

    gps_status = StringProperty("not found")
    gps_longitude = StringProperty()
    gps_latitude = StringProperty()
    gps_altitude = StringProperty()
    gps_speed = StringProperty()
    gps_climb = StringProperty()
    gps_satellites_used = StringProperty()
    gps_precision = StringProperty()

    def __init__(self):
        Screen.__init__(self, name="overview")
        self.network = Network(self.cb_network)
        self.gps = GPS(self.cb_gps)
        self.network.start()
        self.gps.start()

    def cb_network(self, data):
        log.debug("network changed")
        self.network_status = "connected"
        wifi_supplied = False
        eth_supplied = False
        for k in data.keys():
            if k.startswith('wl'):
                log.debug("wifi has new ip: " + data[k])
                self.wifi_status = "connected"
                self.wifi_ip = data[k]
                wifi_supplied = True
            if k.startswith('e'):
                log.debug("ethernet has new ip: " + data[k])
                self.eth_status = "connected"
                self.eth_ip = data[k]
                eth_supplied = True
        if not wifi_supplied:
            log.debug("wifi is disconnected")
            self.wifi_status = "disconnected"
            self.wifi_essid = ""
            self.wifi_ip = ""
        if not eth_supplied:
            log.debug("ethernet is disconnected")
            self.eth_status = "disconnected"
            self.eth_ip = ""

    def cb_gps(self, data):
        self.gps_status = data["status"]
        if self.gps_status != "not found":
            log.debug("got gps location")
            self.gps_longitude = data["longitude"]
            self.gps_latitude = data["latitude"]
            self.gps_altitude = data["altitude"]
            self.gps_speed = data["speed"]
            self.gps_climb = data["climb"]
            self.gps_satellites_used = data["satellites_used"]
            self.gps_precision = data["precision"]


class MainMenu(Screen):
    def __init__(self):
        Screen.__init__(self, name="main_menu")


class SpeechController(Thread):
    daemon = True
    do_run = False
    handle = None
    recorded_frames = []
    num_keywords = 0
    keyword_names = None  # todo

    def __init__(self):
        Thread.__init__(self)
        self.do_run = isdir("porcupine/")
        if self.do_run:
            # todo fill sensitivities parameter
            self.handle = Porcupine(
                self.get_porcupine_library(),
                "porcupine/lib/common/porcupine_params.pv",
                keyword_file_paths="porcupine/models/",
            )

    @staticmethod
    def get_porcupine_library():
        if Static.is_pi():
            model = open("/proc/device-tree/model").read().lower()
            if "zero" in model or "model a" in model or "model b" in model:
                return "porcupine/lib/raspberry-pi/arm11/"
            elif "pi 2" in model:
                return "porcupine/lib/raspberry-pi/cortex-a7/"
            elif "pi 3" in model:
                return "porcupine/lib/raspberry-pi/cortex-a53/"
        else:
            return "porcupine/lib/linux/x86_64/"  # who still uses i386

    def audio_callback(self, in_data, frame_count, time_info, status):
        if frame_count >= self.handle.frame_length:
            pcm = struct.unpack_from("h" * self.handle.frame_length, in_data)
            result = self.handle.process(pcm)
            if self.num_keywords == 1 and result:
                print('[%s] detected keyword' % str(datetime.now()))
                # add your own code execution here ... it will not block the recognition
            elif self.num_keywords > 1 and result >= 0:
                print('[%s] detected %s' % (str(datetime.now()), self.keyword_names[result]))
                # or add it here if you use multiple keywords

        return None, paContinue

    def run(self):
        pa = PyAudio()
        astrm = pa.open(rate=self.handle.sample_rate, channels=1, format=paInt16, input=True,
                        frames_per_buffer=self.handle.frame_length, input_device_index=None, stream_callback=self.audio_callback)
        astrm.start_stream()
        while self.do_run:
            sleep(0.1)

        astrm.stop_stream()
        astrm.close()
        pa.terminate()
        self.handle.delete()


if __name__ == '__main__':
    log.debug("going to run")

    Builder.load_file("carpi.kv")

    sm = ScreenManager()
    sm.add_widget(Overview())
    sm.add_widget(MainMenu())
    sm.add_widget(Audio())
    sm.add_widget(AudioAux())
    sm.add_widget(AudioFM())
    sm.add_widget(Wireless())
    sm.add_widget(WirelessWiFi())
    sm.add_widget(WirelessBluetooth())
    sm.add_widget(Map())
    sm.add_widget(Settings())
    sm.add_widget(SettingsAudio())
    sm.add_widget(SettingsWireless())

    if Static.is_pi():
        log.debug("is pi, setting fullscreen")
        Config.set("graphics", "fullscreen", 1)
        Config.set("graphics", "borderless", 1)
        Config.set("graphics", "resizable", 0)
        Config.set("graphics", "show_cursor", 0)
        Config.set("graphics", "height", 480)
        Config.set("graphics", "width", 320)
        Config.write()
    else:
        log.debug("is not pi, setting 320x480 resolution")
        Config.set("graphics", "height", 480)
        Config.set("graphics", "width", 320)
        Config.set("graphics", "resizable", False)
        Config.write()

    class CarPiApp(App):
        def build(self):
            return sm

    app = CarPiApp()
    app.run()
