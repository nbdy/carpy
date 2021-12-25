from carpy import CarPyModule, log, CarPyWidget
from modulepy import ModuleInformation, ModuleVersion
from kivymd.uix.datatables import MDDataTable
from kivy.metrics import dp
from wifi import Cell, Scheme
from time import sleep


class WiFiWidget(CarPyWidget):
    cache = {}
    table: MDDataTable = None

    def __init__(self, queue):
        CarPyWidget.__init__(self, queue, 1)

    def on_row_selected(self, instance_cell_row):
        log.debug(instance_cell_row)

    def build(self):
        self.table = MDDataTable(
            use_pagination=True,
            column_data=[
                ("BSSID", dp(48), "center", "1fr"),
                ("ESSID", dp(48), "center", "1fr"),
                ("Encryption", dp(24), "center", "1fr"),
                ("RSSI", dp(32), "center", "1fr"),
                ("Status", dp(32), "center", "1fr"),
            ]
        )
        self.table.bind(on_row_press=self.on_row_selected)
        self.add_widget(self.table)

    def update_row(self, data: dict):
        for row in self.table.row_data:
            if row[0] == data["address"]:
                row[1] = data["ssid"]
                row[2] = self.get_encryption(data)
                row[3] = data["quality"]
                break

        log.debug("Update:", data)

    @staticmethod
    def get_encryption(data: dict):
        if data["encrypted"]:
            return data["encryption_type"]
        else:
            return "Open"

    def update_data(self, data: dict):
        if data["address"] in self.cache.keys():
            self.update_row(data)
        else:
            self.cache[data["address"]] = data
            self.table.row_data.append(
                (
                    data["address"],
                    data["ssid"],
                    self.get_encryption(data),
                    data["quality"],
                )
            )


class WiFi(CarPyModule):
    information = ModuleInformation("WiFi", ModuleVersion(1, 0, 0))
    has_widget = True
    widget_cls = WiFiWidget
    device = "wlx8416f9156780"

    def on_start(self):
        log.debug("WiFi started")

    def work(self):
        log.debug("WiFi work")
        aps = Cell.all(self.device)
        for ap in aps:
            log.debug(ap.__dict__)
            self.enqueue(ap.__dict__)
        sleep(1)
