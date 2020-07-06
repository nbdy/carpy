from . import Base, ModuleCategory
from os import environ
import raylibpy


# todo generate the ui for each module
# holds list of available modules
# module functions can have annotations:
# @button(x, y, text, callback, #{IconID}#=None)
# @label(x, y, text)
# @image(x, y, path)
class UI(Base):
    category = ModuleCategory.SYSTEM
    do_start = True
    do_initialize = True

    _ctx = None

    modules = []

    def on_start(self):
        cfg = self.get_configuration()
        environ["RAYLIB_BIN_PATH"] = cfg.raylib_binary
        r = cfg.screen_resolution
        self._ctx.init(r[0], r[1], "carpy")

    def work(self):
        self._ctx.new_frame()

        self._ctx.render()
