from runnable import Runnable
from enum import Enum, unique


@unique
class ModuleCategory(Enum):
    """
    modules get loaded by 'category'
    0 gets loaded first, 1 second, etc
    -1 is just a placeholder
    """
    NONE = -1
    SYSTEM = 0
    MEDIA = 1
    NAVIGATION = 2


class Base(Runnable):
    """
    start indicates if the object should get started by the manager
    """
    do_initialize = False
    do_start = False
    category = ModuleCategory.NONE

    get_logger = None
    get_configuration = None
    get_module = None

    def __init__(self, get_logger, get_configuration, get_module):
        """
        initializes the module object
        :param get_logger: function from the manager, allows to get the logger without storing a reference of it
        :param get_configuration: function from the manager, allows to get the configuration without storing a reference
        :param get_module: function from the manager, which is able to get another module by its type (ecs style)
        """
        Runnable.__init__(self)
        self.get_logger = get_logger
        self.get_configuration = get_configuration
        self.get_module = get_module

    def work(self):
        raise NotImplementedError("When extending the Base Module you should overwrite the work() function.")
