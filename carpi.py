from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname, isfile, isdir
from os import listdir
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon
from subprocess import check_output
from guizero import App, Text

from subprocess import check_output, CalledProcessError


log.add(dirname(abspath(__file__)) + "/output.log", enqueue=True, backtrace=True)

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


class Network(object):
    @staticmethod
    def get_network_interface(prefix):
        for iface in netifaces.interfaces():
            if iface.startswith(prefix):
                return iface
        return None

    @staticmethod
    def get_connected_essid():
        try:
            o = str(check_output(["iwgetid"]))
        except CalledProcessError:
            log.exception("iwgetid exception")
            return ""
        if "ESSID" not in o:
            return ""
        return o.split(':"')[1].split('"')[0]

    @staticmethod
    def get_status(prefix, family=netifaces.AF_INET):
        iface = Network.get_network_interface(prefix)
        if iface is None:
            return None
        try:
            return netifaces.ifaddresses(iface)[family]
        except KeyError:
            log.exception("get status '" + iface + "' keyerror exception")
            return None

    @staticmethod
    def get_wifi_connected_string():
        if Network.get_status("wl") is None:
            return "not connected"
        return "connected"

    @staticmethod
    def get_wifi_connected_ip():
        s = Network.get_status("wl")
        if s is None:
            return ""
        return s[0]["addr"]


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

    def run(self):
        log.debug("running")
        client = gps(mode=WATCH_ENABLE)
        while self.do_run:
            client.next()
            if client.fix != self.current_position:
                log.debug("position has changed; informing main")
                self.current_position = client.fix
                self.callback(client.fix)
            log.debug("sleeping for " + str(self.sleep_time))
            sleep(self.sleep_time)

    def stop(self):
        self.do_run = False


class WiFi(Thread):
    daemon = True
    do_run = False

    iface = None
    callback = None

    def __init__(self, callback, iface="wlan0mon"):
        Thread.__init__(self)
        self.callback = callback
        self.do_run = True
        self.iface = iface

    def _scapy_cb(self, pkt):
        if pkt.haslayer(Dot11):
            pass

    def _scapy_stop_filter(self, pkt):
        return not self.do_run

    def run(self):
        sniff(iface=self.iface, lfilter=self._scapy_cb, stop_filter=self._scapy_stop_filter)

    def stop(self):
        self.do_run = False


# todo: support nested albums
class AudioLibraryManager(object):
    directory = None
    albums = []
    songs = []

    @staticmethod
    def append_slash(data):
        if not data.endswith("/"):
            data += "/"
        return data

    @staticmethod
    def get_songs_in_dir(directory):
        directory = AudioLibraryManager.append_slash(directory)
        songs = []
        for fp in listdir(directory):
            if isfile(fp) and fp[-4:-1] in [".wav", ".mp3"]:
                songs.append(directory + fp)

    @staticmethod
    def get_albums_in_dir(directory):
        directory = AudioLibraryManager.append_slash(directory)
        albums = []
        for fp in listdir(directory):
            if isdir(fp):
                albums.append(fp)
        return albums

    def __init__(self, directory="~/Music/"):
        directory = self.append_slash(directory)
        self.directory = directory

    def get_albums(self):
        return self.get_albums_in_dir(self.directory)

    def get_all_songs(self):
        songs = []
        for a in self.get_albums():
            songs += self.get_songs_in_dir(a)
        return songs


class FMTransmitter(object):
    current_song = None
    pi_fm_rds_path = "/opt/PiFmRds/src/pi_fm_rds"

    def __init__(self):
        if not isfile(self.pi_fm_rds_path):
            raise Exception("/opt/PiFmRds/src/pi_fm_rds does not exist")

    def play(self, fp):
        if not isfile(fp):
            return False
        if fp.endswith(".mp3"):
            check_output(["sox", "-t", fp, "-t", "wav", "-", "|", "./" + self.pi_fm_rds_path, "-audio", "-"])
            return True
        elif fp.endswith(".wav"):
            check_output(["./" + self.pi_fm_rds_path, "-audio", fp])
            return True
        else:
            log.error("not sure what '" + fp[-4:-1] + "'kind of file extension is")
            return False


class UI(App):
    box = None

    lbl_wifi = None
    lbl_wifi_value_status = None
    lbl_wifi_value_essid = None
    lbl_wifi_value_ip = None

    # 01: main horizontal
    # 10: main vertical
    menu = 0

    def __init__(self, **kwargs):
        super(UI, self).__init__(layout="grid", width=480, height=320)
        log.debug("initializing ui")
        self.bg = "black"
        self.tk.attributes("-fullscreen", True)
        log.debug("initialized ui; displaying")
        self.display()

    def vertical(self):
        pass

    def horizontal(self):
        pass

    def translate(self):
        pass

    def wifi_info(self):
        log.debug("building wifi info screen")
        Text(self, text="wifi:", color="white", grid=[8, 4])
        Text(self, text=Network.get_wifi_connected_string(), color="white", grid=[18, 4])
        Text(self, text=Network.get_connected_essid(), color="white", grid=[38, 4])
        Text(self, text=Network.get_wifi_connected_ip(), color="white", grid=[80, 4])

    def bluetooth_info(self, data):
        log.debug("building bluetooth info screen")
        Text(self, text="bluetooth:", color="white", grid=[8, 8])
        Text(self, text=Bluetooth.get_bluetooth_status_string(), color="white", grid=[19, 8])

    def gps_info(self, data):
        log.debug("building gps info screen")
        Text(self, text="gps:", color="white", grid=[8, 20])
        Text(self, text="todo", color="white", grid=[18, 20])


class Main(object):
    ui = None
    gps = None
    wifi = None

    def __init__(self):
        log.debug("initializing")
        self.gps = GPS(self._gps_callback)
        self.wifi = WiFi(self._wifi_callback)
        self.ui = UI()

    def start(self):
        self.gps.run()
        self.wifi.run()

    def _gps_callback(self, data):
        pass  # todo update position

    def _wifi_callback(self, data):
        pass  # todo check what has been found and inform ui

    def _bluetooth_devices_found_callback(self):
        self.ui.bluetooth_info({})  # todo

    def _wifi_connected_callback(self):
        self.ui.wifi_info()


if __name__ == '__main__':
    log.debug("going to run")
    Main()
