from . import Base, ModuleCategory


class WiFi(Base):
    category = ModuleCategory.SYSTEM
    do_start = False
    do_initialize = False
