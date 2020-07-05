from runnable import Runnable
from os import listdir
from loguru import logger
from time import sleep
from importlib import import_module

from . import Configuration


class Manager(Runnable):
    log: logger = None
    cfg: Configuration = None

    loaded_modules = []
    initialized_modules = []
    started_modules = []

    def __init__(self, log: logger, cfg: Configuration):
        """
        initializes the manager
        :param log: previously set up loguru logger
        :param cfg: previously loaded Configuration
        """
        Runnable.__init__(self)
        self.log = log
        self.cfg = cfg

    def get_configuration(self):
        return self.cfg

    def get_logger(self):
        return self.log

    def get_module(self, t: type, name=None):
        """
        gets a module by its type (and name)
        :param t: object type / class
        :param name: class name
        :return: matching module
        """
        self.log.debug("trying to find module {0}".format(t.__class__))
        for m in self.started_modules:
            if isinstance(m, t):
                if name is not None:
                    if m.__class__ == name:
                        return m
                else:
                    return m
        return None

    def on_start(self):
        """
        loads and starts modules
        :return: None
        """
        self.log.info("starting")
        self.load_modules()
        self.initialize_modules()
        self.start_modules()

    def on_stop(self):
        """
        unloads and stops modules
        :return: None
        """
        self.log.info("stopping")
        self.stop_modules()
        self.unload_modules()

    def work(self):
        """
        sleeps for a bit every loop
        :return: None
        """
        sleep(0.5)

    def load_modules(self):
        """
        loads/imports all modules from the module directory
        :return: None
        """
        self.log.info("loading modules from: {0}".format(self.cfg.modules_directory))
        for m in listdir(self.cfg.modules_directory):
            if m.startswith("__"):
                continue
            m = m.replace(".py", "")
            self.log.debug("found module: {0}".format(m))
            self.loaded_modules.append(getattr(import_module(self.cfg.modules_directory.replace("/", ".") + m), m))
        self.log.info("sorting modules by relevance")
        self.loaded_modules.sort(key=lambda x: x.category.value)
        self.log.debug(self.loaded_modules)

    def initialize_modules(self):
        """
        instantiates all loaded modules and passes the get_* functions
        :return: None
        """
        self.log.info("initializing modules")
        for m in self.loaded_modules:
            if m.do_initialize:
                self.log.debug("initializing {0}".format(m))
                self.initialized_modules.append(m(
                    self.get_logger,
                    self.get_configuration,
                    self.get_module
                ))

    def start_modules(self):
        """
        starts all initialized modules
        :return: None
        """
        self.log.info("starting modules")
        for m in self.initialized_modules:
            if m.do_start:
                self.log.debug("starting {0}".format(m))
                m.start()

    def stop_modules(self):
        """
        stops all started modules
        :return: None
        """
        self.log.info("stopping modules")
        for m in self.started_modules:
            m.stop()

    def unload_modules(self):
        """
        unloads modules
        :return: None
        """
        pass  # todo cleanup
