import gi
from time import sleep
from threading import Thread
from gps import gps, WATCH_ENABLE

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


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


class UI(Gtk.Window):
    box = None

    def __init__(self):
        log.debug("initializing ui")
        Gtk.Window.__init__(self)
        self.fullscreen()
        self.connect("destroy", Gtk.main_quit)
        self.show_all()
        Gtk.main()
        self.refresh(self._build_info_screen)

    def refresh(self, f):
        log.debug("refreshing ui")
        self.remove(self.box)
        f()
        self.add(self.box)
        self.show_all()

    def _build_info_screen(self):
        log.debug("building info screen")
        self.box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, homogeneous=True)
        l = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, homogeneous=False)
        r = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, homogeneous=False)
        self.box.pack_start(l, True, True, 0)
        self.box.pack_start(r, True, True, 0)
        l.pack_start(Gtk.Label("gps:"), True, True, 0)
        r.pack_start(Gtk.Label("todo_status"), True, True, 0)

    def lock(self):
        def lock():
            self.box = self.build_box()
        self.refresh(lock)

    def unlock(self):
        self.refresh(self._assemble_main_menu)


class Main(object):
    ui = None
    gps = None

    def __init__(self):
        log.debug("initializing")
        self.gps = GPS(self._gps_callback)
        self.ui = UI()

    def _gps_callback(self, data):
        pass  # todo update position


if __name__ == '__main__':
    log.debug("going to run")
    Main()
