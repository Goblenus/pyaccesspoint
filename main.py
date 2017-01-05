import sys
import os
import argparse
from pyaccesspoint import AccessPoint


def main():
    if os.geteuid() != 0:
        print("Need root rights.")
        return 1

    parser = argparse.ArgumentParser(description='A small daemon to create a wifi hotspot on linux')
    parser.add_argument('command', choices=['start', 'stop', 'configure'])
    parser.add_argument('-v', '--verbose', required=False, action='store_true')
    parser.add_argument('-c', "--config", required=False, action='store_true')
    parser.add_argument('-cp', "--config_path", required=False, default='/etc/accesspoint/accesspoint.json')
    parser.add_argument('-w', "--wlan", required=False, default='wlan0')
    parser.add_argument('-i', "--inet", required=False, default=None)
    parser.add_argument('-ip', required=False, default='192.168.45.1')
    parser.add_argument('-n', "--netmask", required=False, default='255.255.255.0')
    parser.add_argument('-s', "--ssid", required=False, default='MyAccessPoint')
    parser.add_argument('-p', "--password", required=False, default='1234567890')
    parser.add_argument('-sc', "--save_config", required=False, action='store_true')
    args = parser.parse_args()

    access_point = AccessPoint(args.config_path if args.config else None, args.wlan, args.inet, args.ip, args.netmask,
                               args.ssid, args.password)

    if args.save_config:
        access_point.save_config()

    if args.command == 'configure':
        if not args.config:
            print("Please use --config (and --config_path)")
            return 1

        return access_point.configure()
    elif args.command == 'stop':
        return access_point.stop()
    elif args.command == 'start':
        return access_point.start()

if __name__ == "__main__":
    sys.exit(main())