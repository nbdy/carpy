from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname, isfile, isdir
from os import listdir, geteuid, makedirs, environ
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from subprocess import Popen, PIPE
import sounddevice as sd
import soundfile as sf

from kivy.app import App
from kivy.config import Config
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from kivy.properties import StringProperty
# from kivy.core.window import Window

environ["SDL_FBDEV"] = "/dev/fb0"

RUNNING_PATH = dirname(abspath(__file__)) + "/"

if not isdir(RUNNING_PATH + "log/"):
    makedirs(RUNNING_PATH + "log/")

log.add(RUNNING_PATH + "log/output.log", enqueue=True, backtrace=True)

Config.set("kivy", "log_enable", 1)
Config.set("kivy", "log_level", "debug")
Config.set("kivy", "log_dir", RUNNING_PATH + "log/")

# todo
# labels for wifi
# - is connected
# - - to essid
# - - signal strength
#
# labels for gps
# - has fix
# - - lng / lat
# - - speed
#
# rpi radio sender
# https://howtoraspberrypi.com/create-radio-transmitter-raspberry-pi/


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
            for prefix in ['enp', 'wl', 'eth']:
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
        self.do_run = True
        log.debug("initialized gps")

    def parse_current_position(self, c):
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
        client = gps(mode=WATCH_ENABLE)
        while self.do_run:
            client.next()
            if client.fix != self.current_position:
                self.parse_current_position(client)
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
    albums = []
    songs = []
    path = None

    @staticmethod
    def get_songs_in_dir(directory):
        directory = Static.append_slash(directory)
        songs = []
        for fp in listdir(directory):
            if isfile(fp) and fp[-4:-1] in [".wav", ".mp3"]:
                songs.append(directory + fp)

    @staticmethod
    def get_albums_in_dir(directory):
        directory = Static.append_slash(directory)
        albums = []
        for fp in listdir(directory):
            if isdir(fp):
                albums.append(fp)
        return albums

    def __init__(self, path= "~/Music/"):
        self.path = Static.append_slash(abspath(path))
        log.debug("initializing with audio directory '" + self.path + "'")
        log.debug("initialized")

    def get_albums(self):
        return self.get_albums_in_dir(self.path)

    def get_all_songs(self):
        songs = []
        for a in self.get_albums():
            songs += self.get_songs_in_dir(a)
        return songs


class Player(Thread):
    daemon = True
    do_run = False

    queue = []
    current_song = None
    cfg = None

    audio_lib = None

    def __init__(self, cfg, audio_lib):
        Thread.__init__(self)
        self.audio_lib = audio_lib
        self.cfg = cfg

    def play(self, fp):
        pass

    def pause(self):
        pass

    def unpause(self):
        pass

    def enqueue(self, fp):
        self.queue.append(fp)

    def enqueue_dir(self, fp):
        self.queue += self.audio_lib.get_songs_in_dir(fp)

    def stop(self):
        pass


class FMTransmitter(Player):
    css = None

    def __init__(self, config, audio_lib):
        Player.__init__(self, config, audio_lib)
        if not isfile(self.cfg.pi_fm_rds_path):
            raise Exception("/opt/PiFmRds/src/pi_fm_rds does not exist")

    def play(self, fp):
        if not isfile(fp):
            return False
        if fp.endswith(".mp3"):
            self.css = Popen(["sox", "-t", fp, "-t", "wav", "-", "|", "./" + self.cfg.pi_fm_rds_path,
                              "-audio", "-"], stdout=PIPE)
            return True
        elif fp.endswith(".wav"):
            self.css = Popen(["./" + self.cfg.pi_fm_rds_path, "-audio", fp], stdout=PIPE)
            return True
        else:
            log.error("not sure what '" + fp[-4:-1] + "'kind of file extension is")
            return False


class AuxOut(Player):
    def play(self, fp):
        self.current_song = fp
        data, fs = sf.read(fp, dtype='float32')
        sd.play(data, fs)

    def pause(self):
        sd.stop()

    def unpause(self):
        ns = self.queue[0]
        self.queue.pop(0)
        self.play(ns)

    def stop(self):
        sd.stop()


class Audio(Screen):
    pass


class AudioAux(Screen):
    pass


class AudioFM(Screen):
    pass


class Wireless(Screen):
    pass


class WirelessWiFi(Screen):
    pass


class WirelessBluetooth(Screen):
    pass


class Settings(Screen):
    pass


class SettingsAudio(Screen):
    pass


class SettingsWireless(Screen):
    pass


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
        self.network_status = "connected"
        wifi_supplied = False
        eth_supplied = False
        for k in data.keys():
            if k.startswith('wl'):
                self.wifi_status = "connected"
                self.wifi_ip = data[k]
                wifi_supplied = True
            elif k.startswith('e'):
                self.eth_status = "connected"
                self.eth_ip = data[k]
                eth_supplied = True
        if not wifi_supplied:
            self.wifi_status = "disconnected"
            self.wifi_essid = ""
            self.wifi_ip = ""
        if not eth_supplied:
            self.eth_status = "disconnected"
            self.eth_ip = ""

    def cb_gps(self, data):
        self.gps_status = data["status"]
        if self.gps_status != "not found":
            self.gps_longitude = data["longitude"]
            self.gps_latitude = data["latitude"]
            self.gps_altitude = data["altitude"]
            self.gps_speed = data["speed"]
            self.gps_climb = data["climb"]
            self.gps_satellites_used = data["satellites_used"]
            self.gps_precision = data["precision"]


class MainMenu(Screen):
    pass


if __name__ == '__main__':
    log.debug("going to run")

    Builder.load_file("carpi.kv")

    sm = ScreenManager()
    sm.add_widget(Overview())
    sm.add_widget(MainMenu(name="main_menu"))
    sm.add_widget(Audio(name="audio"))
    sm.add_widget(AudioAux(name="audio_aux"))
    sm.add_widget(AudioFM(name="audio_fm"))
    sm.add_widget(Wireless(name="wireless"))
    sm.add_widget(WirelessWiFi(name="wireless_wifi"))
    sm.add_widget(WirelessBluetooth(name="wireless_bluetooth"))
    sm.add_widget(Settings(name="settings"))
    sm.add_widget(SettingsAudio(name="settings_audio"))
    sm.add_widget(SettingsWireless(name="settings_wireless"))

    if Static.is_pi():
        log.debug("is pi, setting fullscreen")
        # Config.set("graphics", "fullscreen", 0)
        Config.set("graphics", "left", 0)
        Config.set("graphics", "top", 0)
        Config.set("graphics", "position", "custom")
        Config.set("graphics", "height", 480)
        Config.set("graphics", "width", 320)
    else:
        log.debug("is not pi, setting 320x480 resolution")
        Config.set("graphics", "height", 480)
        Config.set("graphics", "width", 320)
        Config.set("graphics", "resizable", False)
        Config.write()

    class CarPiApp(App):
        kv_directory = "templates"

        def build(self):
            return sm

    CarPiApp().run()
