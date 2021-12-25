from modulepy import ModuleInformation, ModuleVersion
from carpy import CarPyModule, log, CarPyWidget
from time import sleep
from gps import gps, WATCH_ENABLE
from kivy.properties import StringProperty
from kivymd.uix.label import MDLabel


class GPSInformation(CarPyWidget):
    latitude = StringProperty()
    longitude = StringProperty()
    altitude = StringProperty()

    lbl_header: MDLabel = None
    lbl_latitude: MDLabel = None
    lbl_longitude: MDLabel = None
    lbl_altitude: MDLabel = None

    def update_data(self, data: dict):
        self.latitude = str(data["lat"])
        self.longitude = str(data["lon"])
        self.altitude = str(data["alt"])

    def build(self):
        self.lbl_header = MDLabel(text="GPS Information")
        self.add_widget(self.lbl_header)
        self.lbl_header.pos_hint = {"center_x": 0.5, "center_y": 0.9}

        self.lbl_latitude = MDLabel(text=self.latitude)
        self.add_widget(self.lbl_latitude)

        self.lbl_longitude = MDLabel(text=self.longitude)
        self.add_widget(self.lbl_longitude)

        self.lbl_altitude = MDLabel(text=self.altitude)
        self.add_widget(self.lbl_altitude)


class GPS(CarPyModule):
    client: gps = None
    has_widget = True
    information = ModuleInformation("GPS", ModuleVersion(1, 0, 0))
    widget_cls = GPSInformation

    def on_start(self):
        CarPyModule.on_start(self)
        self.client = gps(mode=WATCH_ENABLE)
        log.debug("GPS started")

    def on_stop(self):
        CarPyModule.on_stop(self)
        self.client.close()
        log.debug("GPS stopped")

    def work(self):
        self.client.next()
        self.data = {
            'lat': self.client.fix.latitude,
            'lon': self.client.fix.longitude,
            'alt': self.client.fix.altitude,
            'speed': self.client.fix.speed,
            'time': self.client.utc,
            'sats': self.client.satellites_used,
            'fix': self.client.fix.mode
        }
        log.debug(self.data)
        self.enqueue(self.data)
        sleep(1)
