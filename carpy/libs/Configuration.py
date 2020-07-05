from loguru import logger as log
from os.path import isfile
import jsonpickle


class Configuration(object):
    config = None

    working_directory = "./"
    modules_directory = "carpy/modules/"

    log_directory = "./log/"
    log_file_name = "carpy-{time}.log"
    log_file_rotation = "20 MB"
    log_backtrace = False

    screen_resolution = 1024, 600
    raylib_binary = ""

    disabled_modules = []

    def __init__(self, config, **kwargs):
        """
        initializes the Configuration object
        :param config: config file path
        :param kwargs: other values which can overwrite attributes
        """
        self.config = config
        self.__dict__.update(kwargs)

    @staticmethod
    def load(fp):
        """
        loads a jsonpickled Configuration object from the file system
        :param fp: file path
        :return: Configuration object
        """
        log.debug("loading configuration: {0}".format(fp))
        if not isfile(fp):
            log.warning("{0} does not exist, creating new config".format(fp))
            return Configuration(fp)
        else:
            with open(fp) as i:
                return jsonpickle.decode(i.read())

    def save(self):
        """
        saves the current configuration
        :return:
        """
        log.debug("saving configuration: {0}".format(self.config))
        with open(self.config, "w") as o:
            o.write(jsonpickle.encode(self))

    def update(self, **kwargs):
        """
        updates values which have changed
        does not write None to attributes
        :param kwargs: values to set
        :return: None
        """
        for k in kwargs.keys():
            v = kwargs.get(k)
            if v is not None:
                if k in self.__dict__.keys():
                    if self.__dict__[k] != v:
                        log.debug("{0} = {1} -> {2}".format(k, self.__dict__[k], v))
                        self.__dict__[k] = v
                else:
                    log.debug("{0} = {1}".format(k, v))
