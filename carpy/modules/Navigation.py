from . import Base, ModuleCategory


class Navigation(Base):
    category = ModuleCategory.NAVIGATION
    do_start = False
    do_initialize = False
