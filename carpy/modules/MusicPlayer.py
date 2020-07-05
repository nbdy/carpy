from . import Base, ModuleCategory


class MusicPlayer(Base):
    category = ModuleCategory.MEDIA
    do_start = False
    do_initialize = False
