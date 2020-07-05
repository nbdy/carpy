from . import Base, ModuleCategory


class Bluetooth(Base):
    category = ModuleCategory.SYSTEM
    do_start = False
    do_initialize = False
