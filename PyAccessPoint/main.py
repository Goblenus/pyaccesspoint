import sys
import os
import argparse
from .pyaccesspoint import AccessPoint
import logging
from wireless import Wireless
import netifaces
import socket
import json


def validate_ip(addr):
    try:
        socket.inet_aton(addr)
        return True  # legal
    except socket.error:
        logging.error("Wrong ip %s", str(addr))
        return False  # Not legal


def configure():
    wireless = Wireless()
    wireless_interfaces = wireless.interfaces()
    if not len(wireless_interfaces):
        print('Wireless interface could not be found on your device.')
        return None
    elif len(wireless_interfaces) > 1:
        while True:
            print("Choose interface: ")
            for i in range(0, len(wireless_interfaces)):
                print("{}: {}".format(str(i), wireless_interfaces[i]))
            try:
                wireless_interface_number = int((input("Enter number: ")))
            except:
                continue
            if wireless_interface_number >= len(wireless_interfaces):
                continue
            wlan = wireless_interfaces[wireless_interface_number]
            break
    else:
        wlan = wireless_interfaces[0]
        print('Wlan interface found: {}'.format(wlan))

    remaining_interfaces = netifaces.interfaces()
    remaining_interfaces.remove(wlan)
    if not len(remaining_interfaces):
        inet = None
        print('No network nic could be found on your deivce to interface with the LAN')
    else:
        while True:
            print("Choose interface: ")
            for i in range(0, len(remaining_interfaces)):
                print("{}: {}".format(str(i), remaining_interfaces[i]))
            print("X: Do not use forwarding")
            try:
                remaining_interface_number = input("Enter number: ")
                if remaining_interface_number.lower() == "x":
                    inet = None
                    break
                remaining_interface_number = int(remaining_interface_number)
            except:
                continue
            if remaining_interface_number >= len(remaining_interfaces):
                continue
            inet = remaining_interfaces[remaining_interface_number]
            break

    while True:
        ip = input('Enter an IP address for your ap [192.168.45.1]:')
        ip = '192.168.45.1' if ip == '' else ip

        if not validate_ip(ip):
            continue

        break

    netmask = '255.255.255.0'

    ssid = input('Enter SSID [MyHotspot]:')
    ssid = 'MyHotspot' if ssid == '' else ssid

    password = input('Enter password [1234567890]:')
    password = '1234567890' if password == '' else password

    return create_config_json(wlan, inet, ip, netmask, ssid, password)


def load_config(config_path):
    try:
        with open(config_path) as access_point_config_file:
            dc = json.load(access_point_config_file)

        return dc
    except:
        return None


def save_config(config_path, config_json):
    config_directory = os.path.dirname(config_path)
    if not os.path.exists(config_directory):
        os.makedirs(config_directory)

    with open(config_path, 'w') as access_point_config_file:
        json.dump(config_json, access_point_config_file)

    os.chmod(config_path, 0o600)

    return True


def create_config_json(wlan='wlan0', inet=None, ip='192.168.45.1', netmask='255.255.255.0', ssid='MyAccessPoint',
                       password='1234567890'):
    return {'wlan': wlan, 'inet': inet, 'ip': ip, 'netmask': netmask, 'ssid': ssid, 'password': password}


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
        logging.error("Need root rights.")
        return 1

    logging.basicConfig(format="%(asctime)s ::%(levelname)s:: %(message)s",
                        level=logging.DEBUG if args.verbose else logging.INFO)

    if args.command == 'configure':
        config_json = configure()
        if config_json is None:
            return 1

        save_config(args.config_path, config_json)

        logging.debug("Config saved in: %s", args.config_path)

        return 0

    if args.config:
        config_json = load_config(args.config_path)

        if config_json is None:
            logging.error("Config loading error")
            return 1
    else:
        config_json = create_config_json(args.wlan, args.inet, args.ip, args.netmask, args.ssid, args.password)

        if args.save_config:
            save_config(args.config_path, config_json)

    access_point = AccessPoint(**config_json)

    if args.command == 'stop':
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