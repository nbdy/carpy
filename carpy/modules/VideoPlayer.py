from . import Base, ModuleCategory


class VideoPlayer(Base):
    category = ModuleCategory.MEDIA
    do_start = False
    do_initialize = False
