from __future__ import print_function
from __future__ import absolute_import
from builtins import input
from builtins import range
import os
import json
import socket
from wireless import Wireless
import netifaces
import shutil
import psutil
import subprocess

config = '''
#sets the wifi interface to use, is wlan0 in most cases
interface={2}
#driver to use, nl80211 works in most cases
driver=nl80211
#sets the ssid of the virtual wifi access point
ssid={0}
#sets the mode of wifi, depends upon the devices you will be using. It can be a,b,g,n. Setting to g ensures backward compatiblity.
hw_mode=g
#sets the channel for your wifi
channel=6
#macaddr_acl sets options for mac address filtering. 0 means "accept unless in deny list"
macaddr_acl=0
#setting ignore_broadcast_ssid to 1 will disable the broadcasting of ssid
ignore_broadcast_ssid=0
#Sets authentication algorithm
#1 - only open system authentication
#2 - both open system authentication and shared key authentication
auth_algs=1
#####Sets WPA and WPA2 authentication#####
#wpa option sets which wpa implementation to use
#1 - wpa only
#2 - wpa2 only
#3 - both
wpa=3
#sets wpa passphrase required by the clients to authenticate themselves on the network
wpa_passphrase={1}
#sets wpa key management
wpa_key_mgmt=WPA-PSK
#sets encryption used by WPA
wpa_pairwise=TKIP
#sets encryption used by WPA2
rsn_pairwise=CCMP
#################################
#####Sets WEP authentication#####
#WEP is not recommended as it can be easily broken into
#wep_default_key=0
#wep_key0=qwert    #5,13, or 16 characters
#optionally you may also define wep_key2, wep_key3, and wep_key4
#################################
#For No encryption, you don't need to set any options
'''


class AccessPoint:
    def __init__(self, access_point_config_path="/etc/accesspoint/accesspoint.json", wlan=None, inet=None, ip=None,
                 netmask=None, ssid=None, password=None):
        self.wlan = wlan
        self.inet = inet
        self.ip = ip
        self.netmask = netmask
        self.ssid = ssid
        self.password = password
        self.access_point_config_path = access_point_config_path
        self.hostapd_config_path = "/etc/access_point/hostapd.config"

        if self.access_point_config_path is not None:
            access_point_directory = os.path.dirname(self.access_point_config_path)
            if not os.path.exists(access_point_directory):
                os.makedirs(access_point_directory)

        hostapd_config_derectory = os.path.dirname(self.hostapd_config_path)
        if not os.path.exists(hostapd_config_derectory):
            os.makedirs(hostapd_config_derectory)

    def _load_access_point_config(self):
        try:
            with open(self.access_point_config_path) as access_point_config_file:
                dc = json.load(access_point_config_file)

            self.wlan = dc['wlan']
            self.inet = dc['inet']
            self.ip = dc['ip']
            self.netmask = dc['netmask']
            self.ssid = dc['ssid']
            self.password = dc['password']
        except:
            return False

        return True

    def _write_hostapd_config(self):
        with open(self.hostapd_config_path, 'w') as hostapd_config_file:
            hostapd_config_file.write(config.format(self.ssid, self.password, self.wlan))

    def save_config(self):
        if self.access_point_config_path is None:
            return False

        with open(self.access_point_config_path, 'w') as access_point_config_file:
            json.dump({'wlan': self.wlan, 'inet': self.inet, 'ip': self.ip, 'netmask': self.netmask,
                       'password': self.password, 'ssid': self.ssid}, access_point_config_file)
        return True

    def configure(self):
        wireless = Wireless()
        wireless_interfaces = wireless.interfaces()
        if not len(wireless_interfaces):
            print('Wireless interface could not be found on your device.')
            return False
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
                self.wlan = wireless_interfaces[wireless_interface_number]
                break
        else:
            self.wlan = wireless_interfaces[0]
            print('Wlan interface found: {}'.format(self.wlan))

        remaining_interfaces = netifaces.interfaces()
        remaining_interfaces.remove(self.wlan)
        if not len(remaining_interfaces):
            self.inet = None
            print('No network nic could be found on your deivce to interface with the LAN')
        elif len(remaining_interfaces):
            while True:
                print("Choose interface: ")
                for i in range(0, len(remaining_interfaces)):
                    print("{}: {}".format(str(i), remaining_interfaces[i]))
                print("X: Do not use forwarding")
                try:
                    remaining_interface_number = input("Enter number: ")
                    if remaining_interface_number.lower() == "x":
                        self.inet = None
                        break
                    remaining_interface_number = int(remaining_interface_number)
                except:
                    continue
                if remaining_interface_number >= len(remaining_interfaces):
                    continue
                self.inet = remaining_interfaces[remaining_interface_number]
                break

        while True:
            self.ip = input('Enter an IP address for your ap [192.168.45.1]:')
            self.ip = '192.168.45.1' if self.ip == '' else self.ip

            if not self._validate_ip(self.ip):
                continue

            break

        self.netmask = '255.255.255.0'

        self.ssid = input('Enter SSID [MyHotspot]:')
        self.ssid = 'hotspot_ssid' if self.ssid == '' else self.ssid

        self.password = input('Enter password [1234567890]:')
        self.password = '1234567890' if self.password == '' else self.password

        self.save_config()

        print('Configuration saved. Run "access_point start" to start the router.')

        return True

    def _validate_ip(self, addr):
        try:
            socket.inet_aton(addr)
            return True  # legal
        except socket.error:
            return False  # Not legal

    def _check_dependencies(self):
        check = True

        if shutil.which('hostapd') is None:
            print('hostapd executable not found. Make sure you have installed hostapd.')
            check = False

        if shutil.which('dnsmasq') is None:
            print('dnsmasq executable not found. Make sure you have installed dnsmasq.')
            check = False

        return check

    def _check_interfaces(self):
        print('Verifying interfaces')
        all_interfaces = netifaces.interfaces()

        check = True

        if self.wlan not in all_interfaces:
            print('{} interface was not found. Make sure your wifi is on.'.format(self.wlan))
            check = False

        if self.inet is not None and self.inet not in all_interfaces:
            print(' interface was not found. Make sure you are connected to the internet.'.format(self.inet))
            check = False

        print('done.')

        return check

    def _pre_start(self):
        try:
            # oper = platform.linux_distribution()
            # if oper[0].lower()=='ubuntu' and oper[2].lower()=='trusty':
            # trusty patch
            # print 'applying hostapd workaround for ubuntu trusty.'
            # 29-12-2014: Rather than patching individual distros, lets make it a default.
            result = self.execute_shell('nmcli radio wifi off')
            if "error" in result.lower():
                self.execute_shell('nmcli nm wifi off')
            self.execute_shell('rfkill unblock wlan')
            self.execute_shell('sleep 1')
            print('done.')
        except:
            pass

    def _start_router(self):
        if not self._check_interfaces():
            return False

        self._pre_start()
        s = 'ifconfig ' + self.wlan + ' up ' + self.ip + ' netmask ' + self.netmask
        print('created interface: mon.' + self.wlan + ' on IP: ' + self.ip)
        r = self.execute_shell(s)
        print(r)
        # print('sleeping for 2 seconds.')
        print('wait..')
        self.execute_shell('sleep 2')
        i = self.ip.rindex('.')
        ipparts = self.ip[0:i]

        # enable forwarding in sysctl.
        print('enabling forward in sysctl.')
        r = self.execute_shell('sysctl -w net.ipv4.ip_forward=1')
        print(r.strip())

        if self.inet is not None:
            # enable forwarding in iptables.
            print('creating NAT using iptables: {} <-> {}'.format(self.wlan, self.inet))
            self.execute_shell('iptables -P FORWARD ACCEPT')

            # add iptables rules to create the NAT.
            self.execute_shell('iptables --table nat --delete-chain')
            self.execute_shell('iptables --table nat -F')
            r = self.execute_shell('iptables --table nat -X')
            if len(r.strip()) > 0:
                print(r.strip())
            self.execute_shell('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(self.inet))
            self.execute_shell(
                'iptables -A FORWARD -i {} -o {} -j ACCEPT -m state --state RELATED,ESTABLISHED'
                    .format(self.inet, self.wlan))
            self.execute_shell('iptables -A FORWARD -i {} -o {} -j ACCEPT'.format(self.wlan, self.inet))

        # allow traffic to/from wlan
        self.execute_shell('iptables -A OUTPUT --out-interface {} -j ACCEPT'.format(self.wlan))
        self.execute_shell('iptables -A INPUT --in-interface {} -j ACCEPT'.format(self.wlan))

        # start dnsmasq
        s = 'dnsmasq --dhcp-authoritative --interface={} --dhcp-range={}.20,{}.100,{},4h'\
            .format(self.wlan, ipparts, ipparts, self.netmask)

        print('running dnsmasq')
        print(s)
        r = self.execute_shell(s)
        print(r)

        # ~ f = open(os.getcwd() + '/hostapd.tem','r')
        # ~ lout=[]
        # ~ for line in f.readlines():
        # ~ lout.append(line.replace('<SSID>',SSID).replace('<PASS>',password))
        # ~
        # ~ f.close()
        # ~ f = open(os.getcwd() + '/hostapd.conf','w')
        # ~ f.writelines(lout)
        # ~ f.close()

        # writelog('created: ' + os.getcwd() + '/hostapd.conf')
        # start hostapd
        # s = 'hostapd -B ' + os.path.abspath('run.conf')
        s = 'hostapd -B {}'.format(self.hostapd_config_path)
        print(s)
        print('running hostapd')
        # print('sleeping for 2 seconds.')
        print('wait..')
        self.execute_shell('sleep 2')
        r = self.execute_shell(s)
        print(r)
        print('hotspot is running.')
        return True

    def _stop_router(self):
        if not self.is_running():
            return True

        # bring down the interface
        self.execute_shell('ifconfig mon.' + self.wlan + ' down')

        # stop hostapd
        print('stopping hostapd')
        self.execute_shell('pkill hostapd')

        # stop dnsmasq
        print('stopping dnsmasq')
        self.execute_shell('killall dnsmasq')

        # disable forwarding in iptables.
        print('disabling forward rules in iptables.')
        self.execute_shell('iptables -P FORWARD DROP')

        # delete iptables rules that were added for wlan traffic.
        if self.wlan != None:
            self.execute_shell('iptables -D OUTPUT --out-interface {} -j ACCEPT'.format(self.wlan))
            self.execute_shell('iptables -D INPUT --in-interface {} -j ACCEPT'.format(self.wlan))
        self.execute_shell('iptables --table nat --delete-chain')
        self.execute_shell('iptables --table nat -F')
        self.execute_shell('iptables --table nat -X')

        # disable forwarding in sysctl.
        print('disabling forward in sysctl.')
        r = self.execute_shell('sysctl -w net.ipv4.ip_forward=0')
        print(r.strip())
        # self.execute_shell('ifconfig ' + wlan + ' down'  + IP + ' netmask ' + Netmask)
        # self.execute_shell('ip addr flush ' + wlan)
        print('hotspot has stopped.')
        return True

    def is_running(self):
        proceses = [proc.name() for proc in psutil.process_iter()]
        return 'hostapd' in proceses or 'dnsmasq' in proceses

    def stop(self):
        return self._stop_router()

    def start(self):
        if not self._check_dependencies():
            return False

        if self.is_running():
            return False

        if self.access_point_config_path is not None and os.path.exists(self.access_point_config_path):
            if not self._load_access_point_config():
                return False
        else:
            if self.wlan is None or self.ip is None or self.netmask is None or self.ssid is None \
                    or self.password is None:
                return False

        self._write_hostapd_config()

        return self._start_router()

    def execute_shell(self, command_string):
        p = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        result = p.communicate()

        return result[0].decode()