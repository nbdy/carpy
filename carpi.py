from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname, isfile, isdir
from os import listdir, geteuid
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon
from subprocess import Popen, PIPE, check_output, STDOUT
from json import loads
from jinja2 import Template
import sounddevice as sd
import soundfile as sf
from sys import argv
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


class Network(Thread):
    daemon = True
    do_run = False

    cfg = None
    callback = None

    @staticmethod
    def get_network_interface(prefix):
        for iface in netifaces.interfaces():
            if iface.startswith(prefix):
                return iface
        return None

    @staticmethod
    def wifi_essid():
        try:
            o = str(check_output(["iwgetid", "-r"], stderr=STDOUT))
        except CalledProcessError:
            log.warning("iwgetid exception; wifi does not seem to be available")
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

    def __init__(self, config, callback):
        Thread.__init__(self)
        self.do_run = True
        self.cfg = config
        self.callback = callback

    def _check(self):
        return self.status("wl") is not None

    def run(self):
        while self.do_run:
            s = self._check()
            if s is not None:
                self.callback(s)
            sleep(self.cfg.sleep_time)


class GPS(Thread):
    daemon = True
    do_run = False

    cfg = None
    callback = None

    current_position = None

    def __init__(self, cfg, callback):
        log.debug("initializing gps")
        Thread.__init__(self)
        log.debug("registering callback")
        self.callback = callback
        self.cfg = cfg
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
            log.debug("sleeping for " + str(self.cfg.sleep_time))
            sleep(self.cfg.sleep_time)

    def stop(self):
        self.do_run = False


class WiFi(Thread):
    daemon = True
    do_run = False

    cfg = None
    callback = None

    def __init__(self, config, callback):
        Thread.__init__(self)
        log.debug("initializing wifi")
        self.callback = callback
        self.do_run = True
        self.cfg = cfg
        log.debug("initialized wifi")
        if not Static.is_root():
            log.warning("not root, disabling wifi")
            self.do_run = False
        if self.cfg.interface is None:
            log.warning("no interface, disabling wifi")
            self.do_run = False

    def _scapy_cb(self, pkt):
        if pkt.haslayer(Dot11):
            pass

    def _scapy_stop_filter(self, pkt):
        return not self.do_run

    def run(self):
        if self.do_run:
            sniff(iface=self.cfg.interface, lfilter=self._scapy_cb, stop_filter=self._scapy_stop_filter)

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
    albums = []
    songs = []
    cfg = None

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

    def __init__(self, cfg):
        self.cfg = cfg
        self.cfg.path = Static.append_slash(self.cfg.path)
        log.debug("initializing with audio directory '" + self.cfg.path + "'")
        log.debug("initialized")

    def get_albums(self):
        return self.get_albums_in_dir(self.cfg.path)

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


class UI(Gtk.Window):
    cfg = None

    class Actions(object):
        EXTRA_DATA = "data"
        RELOAD = "reload"

        class Audio(object):
            PLAY = 0
            PAUSE = 1
            QUEUE_SONG = 2
            QUEUE_DIRECTORY = 3

        class Player(object):
            AUX = 0
            FM = 1

    class Templates(object):
        FOLDER = "templates/"
        ENTRY = "main.json"
        UI_EXTRA = "template"

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

    get_ctx = None

    @staticmethod
    def build_box(orientation=Gtk.Orientation.VERTICAL, spacing=8, homogeneous=True):
        return Gtk.Box(orientation=orientation, spacing=spacing, homogeneous=homogeneous)

    def __init__(self, get_ctx):
        Gtk.Window.__init__(self)
        log.debug("initializing ui")
        self.get_ctx = get_ctx
        self.fullscreen()
        self.box = self.build_box()
        self.grid = Gtk.Grid()
        self.add(self.box)
        self.connect("destroy", Gtk.main_quit)
        self.show_all()

    def ui_switch_btn_clicked(self, tpl):
        self.load_template(tpl, self.get_ctx(tpl))

    def ui_switch_btn_manufacturer(self, lbl, tpl):
        def cb(btn):
            log.debug("ui button switch has been clicked '" + lbl + "'")
            self.ui_switch_btn_clicked(tpl)
        btn = Gtk.Button.new_with_label(lbl)
        btn.connect("clicked", cb)
        return btn

    def class2widget(self, item):
        cls = item["class"]
        if cls == "label":
            lbl = Gtk.Label(item["text"])
            lbl.set_markup("<span foreground=\"" + item["color"] + "\">")
            return lbl
        elif cls == "button":
            if item["backend_action"] == "reload":
                return self.ui_switch_btn_manufacturer(item["text"], item["template"])
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
        self.box.remove(self.grid)
        self.grid = Gtk.Grid()
        self.add2grid(self.grid, json["items"])
        self.box.add(self.grid)
        self.show_all()


class Configuration(object):
    network = None
    bluetooth = None
    audio_library = None
    player = None
    gps = None
    wifi = None

    class WiFi(object):
        interface = "wlan0mon"

    class GPS(object):
        sleep_time = 2

    class Player(object):
        fm = None
        aux = None

        class Aux(object):
            dummy = None

        class FMTransmitter(object):
            pi_fm_rds_path = "/opt/PiFmRds/src/pi_fm_rds"

        def __init__(self):
            self.fm = Configuration.Player.FMTransmitter()
            self.aux = Configuration.Player.Aux()

    class Network(object):
        sleep_time = 2
        prefix = "wl"  # prefix of network device which will be watched

    class Bluetooth(object):
        device = "/dev/hci0"
        sleep_time = 2

    class AudioLibrary(object):
        path = "~/Music/"

    def __init__(self):
        self.network = Configuration.Network()
        self.bluetooth = Configuration.Bluetooth()
        self.audio_library = Configuration.AudioLibrary()
        self.player = Configuration.Player()
        self.gps = Configuration.GPS()
        self.wifi = Configuration.WiFi()

    @staticmethod
    def help():
        log.info("usage: python3 carpi.py {arguments}")
        log.info("{arguments}:")
        log.info("\t\t\t--help")
        log.info("\t-ns\t--network-sleep-time\t2")
        log.info("\t-np\t--network-device-prefix\twl")
        log.info("\t-bd\t--bluetooth-device\t/dev/hci0")
        log.info("\t-bs\t--bluetooth-sleep-time\t2")
        log.info("\t-ap\t--audio-library-path\t~/Music/")
        log.info("\t-pfmrds\t--player-fm-rds-path\t/opt/PiFmRds/src/pi_fm_rds")
        log.info("\t-gs\t--gps-sleep-time\t2")
        log.info("\t-wi\t--wifi-interface\twlan0mon")
        exit()

    @staticmethod
    def parse_arguments(arguments):
        conf = Configuration()
        i = 0
        while i < len(arguments):
            a = arguments[i]
            if a in ["--help"]:
                Configuration.help()
            elif a in ["-ns", "--network-sleep-time"]:
                conf.network.sleep_time = int(arguments[i + 1])
            elif a in ["-np", "--network-device-prefix"]:
                conf.network.prefix = arguments[i + 1]
            elif a in ["-bd", "--bluetooth-device"]:
                conf.bluetooth.device = arguments[i + 1]
            elif a in ["-bs", "--bluetooth-sleep-time"]:
                conf.bluetooth.sleep_time = int(arguments[i + 1])
            elif a in ["-ap", "--audio-library-path"]:
                conf.audio_library.path = arguments[i + 1]
            elif a in ["-pfmrds", "--player-fm-rds-path"]:
                conf.player.fm.pi_fm_rds_path = arguments[i + 1]
            elif a in ["-gs", "--gps-sleep-time"]:
                conf.gps.sleep_time = int(arguments[i + 1])
            i += 1
        return conf


class Main(Thread):
    cfg = None

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
        self.ui.load_template("main.json", self.__get_ctx("main.json"))
        while self.do_run:
            while Gtk.events_pending():
                Gtk.main_iteration()
            sleep(0.2)

    def stop(self):
        self.wifi.stop()
        self.gps.stop()
        self.do_run = False

    def __init__(self, config):
        Thread.__init__(self)
        self.cfg = config
        log.debug("initializing")
        self.audio_lib = AudioLibrary(self.cfg.audio_library)
        self.player = AuxOut(self.cfg.player.aux, self.audio_lib)
        self.network = Network(self.cfg.network, self._nw_cb)
        self.gps = GPS(self.cfg.gps, self._gps_cb)
        self.wifi = WiFi(self.cfg.wifi, self._wifi_cb)
        self.ui = UI(self.__get_ctx)

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
        return self.__deps2ctx(loads(open(UI.Templates.build_path(fn)).read())["dependencies"])

    def _ui_cb(self, action, **kwargs):
        # UI
        log.debug(action)
        log.debug(kwargs)

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
            self.player = FMTransmitter(self.cfg.player.fm, self.audio_lib)
        elif pid == UI.Actions.Player.AUX:
            self.player = AuxOut(self.cfg.player.aux, self.audio_lib)

    def _gps_cb(self, data):
        self._ui_cb(UI.Actions.RELOAD, template="main.json")

    def _nw_cb(self, data):
        self._ui_cb(UI.Actions.RELOAD, template="main.json")

    def _wifi_cb(self, data):  # todo process data
        self._ui_cb(UI.Actions.RELOAD, template="main.json")


if __name__ == '__main__':
    log.debug("going to run")
    cfg = Configuration.parse_arguments(argv)
    m = Main(cfg)
    try:
        m.start()
        m.join()
    except KeyboardInterrupt:
        log.info("caught ctrl+c; stopping")
        m.stop()
