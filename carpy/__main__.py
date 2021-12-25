from argparse import ArgumentParser
from carpy.CarPyApp import CarPyApp


def main():
    ap = ArgumentParser()
    ap.add_argument('-md', '--module-directory', default='modules', help='modules directory')
    args = ap.parse_args()

    cfg = {}

    if args.module_directory:
        cfg['module_directory'] = args.module_directory

    CarPyApp(cfg).run()


if __name__ == '__main__':
    main()
