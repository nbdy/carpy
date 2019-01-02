from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE
from loguru import logger as log
import netifaces
from os.path import abspath, dirname

from pyglet.window import Window
from pyglet.text import Label
from pyglet import app as pyglapp

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


class UI(Window):
    box = None

    lbl_wifi = None
    lbl_wifi_value_status = None
    lbl_wifi_value_essid = None
    lbl_wifi_value_ip = None

    # 0: main
    menu = 0

    def __init__(self):
        super(UI, self).__init__()
        log.debug("initializing ui")
        self.set_fullscreen(True)
        # self.set_size(480, 320)
        self.update_wifi_info()
        self.lbl_bluetooth = Label("bluetooth:")
        self.lbl_bluetooth.x = 4
        self.lbl_bluetooth.y = 292
        log.debug("initialized ui")

    def update_wifi_info(self):
        self.lbl_wifi = Label("wifi:", x=self.width//2, y=self.height//2, font_size=300)
        self.lbl_wifi_value_status = Label(Network.get_wifi_connected_string())
        self.lbl_wifi_value_status.x = 42
        self.lbl_wifi_value_status.y = 306
        self.lbl_wifi_value_essid = Label(Network.get_connected_essid())
        self.lbl_wifi_value_essid.x = 142
        self.lbl_wifi_value_essid.y = 306
        self.lbl_wifi_value_ip = Label(Network.get_wifi_connected_ip())
        self.lbl_wifi_value_ip.x = 336
        self.lbl_wifi_value_ip.y = 306

    def on_draw(self):
        self.clear()
        if self.menu == 0:
            self.lbl_wifi.draw()
            self.lbl_wifi_value_status.draw()
            self.lbl_wifi_value_essid.draw()
            self.lbl_wifi_value_ip.draw()
            self.lbl_bluetooth.draw()


class Main(object):
    ui = None
    gps = None

    def __init__(self):
        log.debug("initializing")
        self.gps = GPS(self._gps_callback)
        self.ui = UI()
        log.debug("running pyglet app")
        pyglapp.run()

    def _gps_callback(self, data):
        pass  # todo update position


if __name__ == '__main__':
    log.debug("going to run")
    Main()
