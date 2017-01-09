import sys
import os
import argparse
from .pyaccesspoint import AccessPoint
import logging


def main():
    parser = argparse.ArgumentParser(description='A utility create a wifi hotspot on linux',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('command', choices=['start', 'stop', 'configure'])
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='output debug information')
    parser.add_argument('-c', "--config", required=False, action='store_true', help='use config file')
    parser.add_argument('-cp', "--config_path", required=False, default='/etc/accesspoint/accesspoint.json',
                        help='path to config file')
    parser.add_argument('-w', "--wlan", required=False, default='wlan0',
                        help='wi-fi interface that will be used to create hotspot')
    parser.add_argument('-i', "--inet", required=False, default=None, help='forwarding interface')
    parser.add_argument('-ip', required=False, default='192.168.45.1', help='ip address of this machine in new '
                                                                            'network')
    parser.add_argument('-n', "--netmask", required=False, default='255.255.255.0',
                        help='no idea what to put here as help, if don\'t know what is it don\'t change this parameter')
    parser.add_argument('-s', "--ssid", required=False, default='MyAccessPoint', help='name of new hotspot')
    parser.add_argument('-p', "--password", required=False, default='1234567890',
                        help='password that can be used to connect to created hotspot')
    parser.add_argument('-sc', "--save_config", required=False, action='store_true',
                        help='set this parameter if you want to save config file')
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.warning("Need root rights.")
        return 1

    logging.basicConfig(format="%(asctime)s ::%(levelname)s:: %(message)s",
                        level=logging.DEBUG if args.verbose else logging.INFO)

    access_point = AccessPoint(args.config_path if args.config else None, args.wlan, args.inet, args.ip, args.netmask,
                               args.ssid, args.password)

    if args.save_config:
        access_point.save_config()

    if args.command == 'configure':
        if not args.config:
            logging.error("Please use --config (and --config_path)")
            out = 1
        else:
            out = access_point.configure()
    elif args.command == 'stop':
        out = access_point.stop()
        if out:
            logging.info("Stopped")
    elif args.command == 'start':
        out = access_point.start()
        if out:
            logging.info("Started")
    else:
        out = 0

    return out

if __name__ == "__main__":
    sys.exit(main())