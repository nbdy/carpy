from argparse import ArgumentParser
from loguru import logger as log

from carpy.libs import Manager, Configuration


def main():
    log.info("*" * 20 + " carpy " + "*" * 20)
    log.debug("parsing args")
    ap = ArgumentParser()
    # you can pass a config file, but passed arguments will overwrite the parameters in the config file
    ap.add_argument("-c", "--config", help="configuration file", default="config.pjs", type=str)
    # system stuff
    ap.add_argument("-wd", "--working-directory", help="path to working directory", type=str)
    ap.add_argument("-sr", "--screen-resolution", help="screen resolution / X,Y", type=str)
    ap.add_argument("-rb", "--raylib-binary", help="path to raylib.so", type=str)
    # module stuff
    ap.add_argument("-md", "--modules-directory", help="path to python modules", type=str)
    # logging stuff
    ap.add_argument("-ld", "--log-directory", help="path to log files", type=str)
    ap.add_argument("-lfn", "--log-file-name", help="log file name", type=str)
    ap.add_argument("-lfr", "--log-file-rotation", help="rotate after xMB", type=int)
    ap.add_argument("-lbt", "--log-backtrace", action="store_true", help="log backtraces")

    a = ap.parse_args()

    cfg = Configuration.load(a.config)

    if a.log_directory:
        if not a.log_directory.endswith("/"):
            a.log_directory += "/"

    if a.screen_resolution:
        if "," in a.screen_resolution:
            sr = a.screen_resolution.split(",")
            a.screen_resolution = sr[0], sr[1]

    cfg.update(**vars(a))
    cfg.save()

    log.debug("using working directory: {0}".format(cfg.working_directory))
    log.debug("using screen resolution: {0}".format(cfg.screen_resolution))

    lp = "{0}{1}".format(cfg.log_directory, cfg.log_file_name)
    lr = cfg.log_file_rotation
    lb = cfg.log_backtrace
    log.debug("logging to: {0}".format(lp))
    log.debug("rotating after: {0}".format(lr))
    log.debug("logging backtraces: {0}".format(lb))
    log.add(lp, rotation=lr, enqueue=True, backtrace=lb, diagnose=lb)

    m = Manager(log, cfg)
    try:
        m.start()
    except KeyboardInterrupt:
        m.stop()


if __name__ == '__main__':
    main()
