from os import getcwd, geteuid
from sys import argv
from loguru import logger as log


class Setup(object):
    SCRIPT = "carpi.py"
    ROTATE_SCRIPT = "rotate.sh"
    HEADLESS_AUTOSTART_PATH = "/etc/rc.local"
    AUTOSTART_PATH = "~/.config/lxsession/LXDE/autostart"

    @staticmethod
    def read_autostart_file():
        with open(Setup.AUTOSTART_PATH) as o:
            return o.readlines()

    @staticmethod
    def already_autostart_installed():
        for l in Setup.read_autostart_file():
            if l.endswith(Setup.SCRIPT):
                return True
        return False

    @staticmethod
    def _install_autostart():
        log.info("installing to autostart")
        with open(Setup.AUTOSTART_PATH, 'a') as o:
            # o.write("@lxterminal -e cd " + getcwd() + "/; git pull")
            o.write("@lxterminal -e /usr/bin/sudo /usr/bin/python3 " + getcwd() + "/" + Setup.SCRIPT)
        return True

    @staticmethod
    def _install_rotate_screen_script():
        log.info("putting rotate script into autostart")
        with open(Setup.AUTOSTART_PATH, 'a') as o:
            o.write("@" + getcwd() + "/rotate.sh")
        return True

    @staticmethod
    def install_autostart(rotate=False):
        if rotate:
            Setup._install_rotate_screen_script()
        if Setup.already_autostart_installed():
            log.info("autostart already installed")
            return True
        Setup._install_autostart()

    @staticmethod
    def _uninstall_autostart():
        log.info("uninstalling autostart")
        _o = Setup.read_autostart_file()
        with open(Setup.AUTOSTART_PATH, 'w') as o:
            for l in _o:
                if Setup.SCRIPT not in l:
                    o.write(l + "\n")

    @staticmethod
    def uninstall_autostart(rotate=False):
        if rotate:
            Setup._uninstall_rotate_screen_script()
        if not Setup.already_autostart_installed():
            log.info("autostart already not enabled")
            return True
        Setup._uninstall_autostart()

    @staticmethod
    def _uninstall_rotate_screen_script():
        pass  # todo

    @staticmethod
    def help():
        log.info("usage: python3 carpi.py [rotate] {other arguments}")
        log.info("[rotate]: -r\t--rotate")
        log.info("{other arguments}:")
        log.info("\t-i\t--install")
        log.info("\t-u\t--uninstall")
        exit()

    @staticmethod
    def parse_arguments(arguments):
        i = 0
        r = True
        log.info("parsing args")
        while i < len(arguments):
            a = arguments[i]
            if a in ["-i", "--install"]:
                Setup.install_autostart(r)
            elif a in ["-u", "--uninstall"]:
                Setup.uninstall_autostart(r)
            elif a in ["-r", "--rotate"]:
                r = True
            else:
                Setup.help()


def should_not_be_root():
    if geteuid() == 0:
        log.error("should not modify", Setup.AUTOSTART_PATH, "with root permissions")
        exit()


def should_be_root():
    if geteuid() != 0:
        log.error("need root for apt calls and display driver install")
        exit()


if __name__ == '__main__':
    Setup.parse_arguments(argv)
