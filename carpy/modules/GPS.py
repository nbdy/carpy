from . import Base, ModuleCategory

from time import sleep
from gps import gps, WATCH_ENABLE


class GPS(Base):
    category = ModuleCategory.SYSTEM
    do_start = False
    do_initialize = False

    _gps = None
    current_position = None

    def on_start(self):
        self._gps = gps(mode=WATCH_ENABLE)

    def work(self):
        self.current_position = self._gps.next()
        sleep(0.2)
