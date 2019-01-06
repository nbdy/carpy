from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname, isfile, isdir
from os import listdir, geteuid
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon
from subprocess import Popen, PIPE, check_output
from json import loads
from jinja2 import Template
import sounddevice as sd
import soundfile as sf
from subprocess import check_output, CalledProcessError
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

RUNNING_PATH = dirname(abspath(__file__)) + "/"

log.add(RUNNING_PATH + "output.log", enqueue=True, backtrace=True)

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
    def wifi_essid():
        try:
            o = str(check_output(["iwgetid", "-r"]))
        except CalledProcessError:
            log.exception("iwgetid exception")
            return ""
        if "ESSID" not in o:
            return ""
        return o.split(':"')[1].split('"')[0]

    @staticmethod
    def status(prefix, family=netifaces.AF_INET):
        iface = Network.get_network_interface(prefix)
        if iface is None:
            return None
        try:
            return netifaces.ifaddresses(iface)[family]
        except KeyError:
            log.exception("get status '" + iface + "' keyerror exception")
            return None

    @staticmethod
    def wifi_status():
        if Network.status("wl") is None:
            return "not connected"
        return "connected"

    @staticmethod
    def wifi_ip():
        s = Network.status("wl")
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
                log.debug("position has changed; informing main.json")
                self.parse_current_position(client)
                self.callback(self.current_position)
            log.debug("sleeping for " + str(self.sleep_time))
            sleep(self.sleep_time)

    def stop(self):
        self.do_run = False


class WiFi(Thread):
    daemon = True
    do_run = False

    iface = None
    callback = None

    def __init__(self, callback, iface=Network.get_network_interface("wl")):
        Thread.__init__(self)
        log.debug("initializing wifi")
        self.callback = callback
        self.do_run = True
        self.iface = iface
        log.debug("initialized wifi")
        if not Static.is_root():
            log.warning("not root, disabling wifi")
            self.do_run = False
        if self.iface is None:
            log.warning("no interface, disabling wifi")
            self.do_run = False

    def _scapy_cb(self, pkt):
        if pkt.haslayer(Dot11):
            pass

    def _scapy_stop_filter(self, pkt):
        return not self.do_run

    def run(self):
        if self.do_run:
            sniff(iface=self.iface, lfilter=self._scapy_cb, stop_filter=self._scapy_stop_filter)

    def stop(self):
        self.do_run = False


class Static(object):
    @staticmethod
    def str2orientation(data):
        if data.lower() in ["v", "vertical"]:
            return Gtk.Orientation.VERTICAL
        elif data.lower() in ["h", "horizontal"]:
            return Gtk.Orientation.HORIZONTAL
        else:
            return Gtk.Orientation.HORIZONTAL

    @staticmethod
    def str2positiontype(data):
        data = data.lower()
        if data in ["top", "t"]:
            return Gtk.PositionType.TOP
        elif data in ["bottom", "b"]:
            return Gtk.PositionType.BOTTOM
        elif data in ["left", "l"]:
            return Gtk.PositionType.LEFT
        elif data in ["right", "r"]:
            return Gtk.PositionType.RIGHT

    @staticmethod
    def append_slash(data):
        if not data.endswith("/"):
            data += "/"
        return data

    @staticmethod
    def is_root():
        return geteuid() == 0


# todo: support nested albums
class AudioLibrary(object):
    directory = None
    albums = []
    songs = []

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

    def __init__(self, directory="~/Music/"):
        log.debug("initializing with audio directory '" + directory + "'")
        directory = Static.append_slash(directory)
        self.directory = directory
        log.debug("initialized")

    def get_albums(self):
        return self.get_albums_in_dir(self.directory)

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

    audio_lib = None

    def __init__(self, audio_lib):
        Thread.__init__(self)
        self.audio_lib = audio_lib

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
    pi_fm_rds_path = "/opt/PiFmRds/src/pi_fm_rds"
    css = None

    def __init__(self, audio_lib):
        Player.__init__(self, audio_lib)
        if not isfile(self.pi_fm_rds_path):
            raise Exception("/opt/PiFmRds/src/pi_fm_rds does not exist")

    def play(self, fp):
        if not isfile(fp):
            return False
        if fp.endswith(".mp3"):
            self.css = Popen(["sox", "-t", fp, "-t", "wav", "-", "|", "./" + self.pi_fm_rds_path,
                              "-audio", "-"], stdout=PIPE)
            return True
        elif fp.endswith(".wav"):
            self.css = Popen(["./" + self.pi_fm_rds_path, "-audio", fp], stdout=PIPE)
            return True
        else:
            log.error("not sure what '" + fp[-4:-1] + "'kind of file extension is")
            return False


class AuxOut(Player):
    def __init__(self, audio_lib):
        Player.__init__(self, audio_lib)

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


class UI(Gtk.Window):
    class Actions(object):
        EXTRA_DATA = "data"

        class Audio(object):
            PLAY = 0
            PAUSE = 1
            QUEUE_SONG = 2
            QUEUE_DIRECTORY = 3

        class Player(object):
            AUX = 0
            FM = 1

        class UI(object):
            RELOAD = 0
            TEMPLATE = "ui-template"
            DEPENDENCIES = "ui-dependencies"

    class Templates(object):
        FOLDER = "templates/"
        ENTRY = "main.json"

        @staticmethod
        def build_path(fn):
            return RUNNING_PATH + UI.Templates.FOLDER + fn

    current_template = None
    width = 480
    height = 320
    box = None
    grid = None
    gtkt = None
    callback = None

    @staticmethod
    def build_box(orientation=Gtk.Orientation.VERTICAL, spacing=8, homogeneous=True):
        return Gtk.Box(orientation=orientation, spacing=spacing, homogeneous=homogeneous)

    def __init__(self, callback):
        Gtk.Window.__init__(self)
        log.debug("initializing ui")
        self.callback = callback
        self.fullscreen()
        self.box = self.build_box()
        self.connect("destroy", Gtk.main_quit)
        self.show_all()
        log.debug("running gtk main loop")

        def gtk_main_loop():
            Gtk.main()
        self.gtkt = Thread(target=gtk_main_loop, daemon=True)
        self.gtkt.start()
        log.debug("initialized wifi")

    def class2widget(self, item):
        cls = item["class"]
        if cls == "label":
            lbl = Gtk.Label(item["text"])
            lbl.set_markup("<span foreground=\"" + item["color"] + "\">")
            return lbl
        elif cls == "button":
            def cb():
                self.callback(UI.Actions.UI.RELOAD, item["ui-template"])
            btn = Gtk.Button.new_with_label(item["text"])
            btn.connect("clicked", cb)
            return btn
        elif cls == "box":
            box = Gtk.Box(spacing=item["spacing"], homogeneous=item["homogeneous"],
                          orientation=Static.str2orientation(item["orientation"]))
            if len(item["items"]) > 0:
                box = UI.add_to_box(box, item["items"])
            return box
        elif cls == "grid":
            grid = Gtk.Grid()
            if len(item["items"]) > 0:
                grid = UI.add_to_box(grid, item["items"])
            return grid

    @staticmethod
    def sort_items(items):
        lst = []
        for item in items.keys():
            i = items[item]
            i["key"] = item
            lst.append(i)
        return sorted(lst, key=lambda k: k["id"])

    def add2grid(self, box, items):
        tmpstrg = {}
        items = UI.sort_items(items)
        for i in items:
            tmpstrg[i["key"]] = self.class2widget(i)
            a = i["action"].lower()
            if a == "pack_start":
                box.pack_start(tmpstrg[i["key"]], True, True, 0)
            elif a == "pack_end":
                box.pack_end(tmpstrg[i["key"]], True, True, 0)
            elif a == "add":
                box.add(tmpstrg[i["key"]])
            elif a == "attach":
                p = i["params"]
                box.attach(tmpstrg[i["key"]], p["left"], p["top"], p["width"], p["height"])
            elif a == "attach_next_to":
                p = i["params"]
                box.attach_next_to(tmpstrg[i["key"]], tmpstrg[p["neighbor_key"]],
                                   Static.str2positiontype(p["position_type"]),
                                   p["width"], p["height"])

    def load_template(self, name, ctx):
        self.current_template = name
        with open(UI.Templates.build_path(name)) as data:
            tpl = Template(data.read())
        json = loads(tpl.render(ctx=ctx))
        self.remove(self.box)
        self.grid = Gtk.Grid()
        self.box = Gtk.Box()
        self.add2grid(self.grid, json["items"])
        self.box.add(self.grid)
        self.add(self.box)
        self.show_all()


class Main(Thread):
    ui = None
    gps = None
    wifi = None
    network = None

    audio_lib = None
    player = None

    do_run = True

    def run(self):
        log.debug("starting gps")
        self.gps.start()
        log.debug("starting wifi")
        self.wifi.start()
        log.debug("displaying main.json")
        self.ui.load_template("main.json", self.__deps2ctx(
            loads(open(RUNNING_PATH + "templates/main.json").read())["dependencies"]))
        while self.do_run:
            log.debug("sleeping for 2 seconds")
            sleep(2)

    def stop(self):
        self.wifi.stop()
        self.gps.stop()
        self.do_run = False

    def __init__(self):
        Thread.__init__(self)
        log.debug("initializing")
        self.audio_lib = AudioLibrary()
        self.network = Network()
        self.gps = GPS(self._gps_cb)
        self.wifi = WiFi(self._wifi_cb)
        self.ui = UI(self._ui_cb)

    def __deps2ctx(self, deps):
        log.debug(deps)
        ctx = {}
        for dep in deps:
            if dep in self.__dict__.keys():
                ctx[dep] = self.__dict__[dep]
            else:
                log.error(dep + " has not been implemented")
        return ctx

    def __get_ctx(self, fn):
        return self.__deps2ctx(loads(UI.Templates.build_path(fn))["dependencies"])

    def _ui_cb(self, action, **kwargs):
        # UI
        if action == UI.Actions.UI.RELOAD:
            fn = kwargs.get(UI.Actions.UI.TEMPLATE)
            self.ui.load_template(fn, self.__get_ctx(fn))
        # PLAYER
        if action == UI.Actions.Audio.PLAY:
            self.player.play(kwargs.get(UI.Actions.EXTRA_DATA))
        elif action == UI.Actions.Audio.PAUSE:
            self.player.pause()
        elif action == UI.Actions.Audio.QUEUE_SONG:
            self.player.enqueue(kwargs.get(UI.Actions.EXTRA_DATA))
        elif action == UI.Actions.Audio.QUEUE_DIRECTORY:
            self.player.enqueue_dir(kwargs.get(UI.Actions.EXTRA_DATA))

    def _ui_player_selected_cb(self, pid):
        if pid == UI.Actions.Player.FM:
            self.player = FMTransmitter(self.audio_lib)
        elif pid == UI.Actions.Player.AUX:
            self.player = AuxOut(self.audio_lib)

    def _gps_cb(self, data):
        pass  # todo update position

    def _wifi_cb(self, data):
        pass  # todo check what has been found and inform ui


if __name__ == '__main__':
    log.debug("going to run")
    m = Main()
    try:
        m.start()
        m.join()
    except KeyboardInterrupt:
        log.info("caught ctrl+c; stopping")
        m.stop()
