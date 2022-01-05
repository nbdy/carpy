from carpy import CarPyModule, log, CarPyWidget
from modulepy import ModuleInformation, ModuleVersion
from kivymd.uix.datatables import MDDataTable
from kivy.metrics import dp
from kivy.clock import mainthread
from datetime import datetime, timedelta
import NetworkManager
import dbus.mainloop.glib


class WiFiWidget(CarPyWidget):
    cache = {}
    table: MDDataTable = None

    def __init__(self, queue):
        CarPyWidget.__init__(self, queue, 1)

    def on_row_selected(self, table, row):
        log.debug(row)

    def build(self):
        self.table = MDDataTable(
            use_pagination=True,
            rows_num=10,
            pagination_menu_pos="auto",
            column_data=[
                ("BSSID", dp(32), "center", "1fr"),
                ("ESSID", dp(48), "center", "1fr"),
                ("Encryption", dp(24), "center", "1fr"),
                ("Signal", dp(32), "center", "1fr"),
            ]
        )
        self.table.bind(on_row_press=self.on_row_selected)
        self.add_widget(self.table)

    @staticmethod
    def get_encryption(data: dict):
        if data["encrypted"]:
            return data["wpa_flags"]
        else:
            return "Open"

    def get_row_index(self, bssid: str):
        for idx, row in enumerate(self.table.row_data):
            if row[0] == bssid:
                return idx
        return None

    def make_row_tuple(self, data: dict):
        return (
            data["bssid"],
            data["essid"],
            self.get_encryption(data),
            data["strength"]
        )

    def check_for_outdated_entries(self):
        if datetime.now() - self.cache[self.table.row_data[0][0]]["last_seen"] > timedelta(seconds=5):
            self.table.row_data.pop(0)

    @mainthread
    def update_data(self, data: dict):
        if data["bssid"] in self.cache.keys():
            idx = self.get_row_index(data["bssid"])
            self.table.row_data[idx] = self.make_row_tuple(data)
        else:
            self.table.row_data.append(self.make_row_tuple(data))
        self.cache[data["bssid"]] = data


class WiFi(CarPyModule):
    information = ModuleInformation("WiFi", ModuleVersion(1, 0, 0))
    has_widget = True
    widget_cls = WiFiWidget

    @staticmethod
    def ap_to_dict(ap):
        return {
            "bssid": ap.HwAddress,
            "essid": ap.Ssid,
            "strength": ap.Strength,
            "encrypted": ap.Flags & NetworkManager.NM_802_11_AP_FLAGS_PRIVACY,
            "wpa_flags": ap.WpaFlags,
            "last_seen": ap.LastSeen
        }

    def on_start(self):
        log.debug("WiFi on_start")
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        CarPyModule.on_start(self)

    @staticmethod
    def get_first_available_wifi_device():
        for dev in NetworkManager.NetworkManager.GetDevices():
            if dev.DeviceType == NetworkManager.NM_DEVICE_TYPE_WIFI:
                return dev
        return None

    def work(self):
        log.debug("WiFi work")
        dev = self.get_first_available_wifi_device()
        if dev is not None:
            for ap in dev.GetAccessPoints():
                self.enqueue(self.ap_to_dict(ap))
        self.sleep(3)
