from modulepy import ModuleInformation, ModuleVersion
from carpy import CarPyModule, log, CarPyWidget
from gps import gps, WATCH_ENABLE, WATCH_JSON
from kivymd.uix.label import MDLabel
from kivy.clock import mainthread


class GPSInformation(CarPyWidget):
    lbl_header: MDLabel = None
    lbl_latitude: MDLabel = None
    lbl_longitude: MDLabel = None
    lbl_altitude: MDLabel = None
    latitude: MDLabel = None
    longitude: MDLabel = None
    altitude: MDLabel = None

    @mainthread
    def update_data(self, data: dict):
        self.latitude.text = str(data["lat"])
        self.longitude.text = str(data["lon"])
        self.altitude.text = str(data["alt"])

    def build(self):
        self.lbl_header = MDLabel(text="GPS Information")
        self.add_widget(self.lbl_header)
        self.lbl_header.pos_hint = {"center_x": 0.52, "center_y": 0.96}

        self.lbl_latitude = MDLabel(text="Latitude:")
        self.add_widget(self.lbl_latitude)
        self.lbl_latitude.pos_hint = {"center_x": 0.54, "center_y": 0.90}

        self.latitude = MDLabel(text="0")
        self.add_widget(self.latitude)
        self.latitude.pos_hint = {"center_x": 0.65, "center_y": 0.90}

        self.lbl_longitude = MDLabel(text="Longitude:")
        self.add_widget(self.lbl_longitude)
        self.lbl_longitude.pos_hint = {"center_x": 0.54, "center_y": 0.84}

        self.longitude = MDLabel(text="0")
        self.add_widget(self.longitude)
        self.longitude.pos_hint = {"center_x": 0.65, "center_y": 0.84}

        self.lbl_altitude = MDLabel(text="Altitude:")
        self.add_widget(self.lbl_altitude)
        self.lbl_altitude.pos_hint = {"center_x": 0.54, "center_y": 0.78}

        self.altitude = MDLabel(text="0")
        self.add_widget(self.altitude)
        self.altitude.pos_hint = {"center_x": 0.65, "center_y": 0.78}


class GPS(CarPyModule):
    client: gps = None
    has_widget = True
    information = ModuleInformation("GPS", ModuleVersion(1, 0, 0))
    widget_cls = GPSInformation

    def on_start(self):
        CarPyModule.on_start(self)
        self.client = gps(mode=WATCH_ENABLE | WATCH_JSON)
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
        self.sleep(1)
