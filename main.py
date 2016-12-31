#!/usr/bin/env python
# @author: Prahlad Yeri
# @description: Small daemon to create a wifi hotspot on linux
# @license: MIT
from __future__ import print_function
from __future__ import absolute_import
from builtins import input
from builtins import range
from builtins import object
import sys
import os
import argparse
from . import cli
import json
import socket
import platform
import datetime
import time
from wireless import Wireless
import netifaces

config = '''
#sets the wifi interface to use, is wlan0 in most cases
interface=wlan0
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

class Proto(object):
    pass


const = Proto()

# global const = Proto() #struct to hold startup parameters
# const.debug = False
# const.verbose = False
# const.command = 'start'
# const.argv = None

stores = Proto()  # struct to dump misc variables
stores.running = False


def validate_ip(addr):
    try:
        socket.inet_aton(addr)
        return True  # legal
    except socket.error:
        return False  # Not legal


def configure(hotspotd_config, run_conf):
    global wlan, ppp, IP, netmask
    # CHECK WHETHER WIFI IS SUPPORTED OR NOT
    print('Verifying connections')
    wlan = ''
    ppp = ''

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
                wireless_interface_number = int(eval(input("Enter number: ")))
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
        print('No network nic could be found on your deivce to interface with the LAN')
        return False
    elif len(remaining_interfaces) > 1:
        while True:
            print("Choose interface: ")
            for i in range(0, len(remaining_interfaces)):
                print("{}: {}".format(str(i), remaining_interfaces[i]))
            try:
                remaining_interface_number = int(eval(input("Enter number: ")))
            except:
                continue
            if remaining_interface_number >= len(remaining_interfaces):
                continue
            ppp = remaining_interfaces[remaining_interface_number]
            break
    else:
        wlan = wireless_interfaces[0]
        print('Network interface found: {}'.format(ppp))

    while True:
        IP = input('Enter an IP address for your ap [192.168.45.1]:')
        # except: continue
        # print type(IP)
        # sys.exit(0)
        if IP == None or IP == '':
            IP = '192.168.45.1'
        if not validate_ip(IP): continue
        break

    netmask = '255.255.255.0'

    # CONFIGURE SSID, PASSWORD, ETC.
    SSID = input('Enter SSID [joe_ssid]:')
    if SSID == '':
        SSID = 'joe_ssid'

    password = input('Enter 10 digit password [1234567890]:')
    if password == '':
        password = '1234567890'

    with open(run_conf, 'w') as run_conf_file:
        run_conf_file.write(config.format(SSID, password))

    print('created hostapd configuration: {}'.format(run_conf))

    dc = {'wlan': wlan, 'inet': ppp, 'ip': IP, 'netmask': netmask, 'SSID': SSID, 'password': password}
    with open(hotspotd_config, 'w') as hotspotd_config_file:
        json.dump(dc, hotspotd_config_file)

    print(dc)
    print('Configuration saved. Run "hotspotd start" to start the router.')

    # CHECK WIFI DRIVERS AND ISSUE WARNINGS

    return True


def check_dependencies():
    # CHECK FOR DEPENDENCIES
    if len(cli.check_sysfile('hostapd')) == 0:
        print('hostapd executable not found. Make sure you have installed hostapd.')
        return False
    elif len(cli.check_sysfile('dnsmasq')) == 0:
        print('dnsmasq executable not found. Make sure you have installed dnsmasq.')
        return False
    else:
        return True


def check_interfaces():
    global wlan, ppp
    print('Verifying interfaces')
    s = cli.execute_shell('ifconfig')
    lines = s.splitlines()
    bwlan = False
    bppp = False

    for line in lines:
        if not line.startswith(' ') and len(line) > 0:
            text = line.split(' ')[0]
            if text.startswith(wlan):
                bwlan = True
            elif text.startswith(ppp):
                bppp = True

    if not bwlan:
        print(wlan + ' interface was not found. Make sure your wifi is on.')
        return False
    elif not bppp:
        print(ppp + ' interface was not found. Make sure you are connected to the internet.')
        return False
    else:
        print('done.')
        return True


def pre_start():
    try:
        # oper = platform.linux_distribution()
        # if oper[0].lower()=='ubuntu' and oper[2].lower()=='trusty':
        # trusty patch
        # print 'applying hostapd workaround for ubuntu trusty.'
        # 29-12-2014: Rather than patching individual distros, lets make it a default.
        result = cli.execute_shell('nmcli radio wifi off')
        if "error" in result.lower():
            cli.execute_shell('nmcli nm wifi off')
        cli.execute_shell('rfkill unblock wlan')
        cli.execute_shell('sleep 1')
        print('done.')
    except:
        pass


def start_router(run_conf):
    if not check_dependencies():
        return
    elif not check_interfaces():
        return
    pre_start()
    s = 'ifconfig ' + wlan + ' up ' + IP + ' netmask ' + netmask
    print('created interface: mon.' + wlan + ' on IP: ' + IP)
    r = cli.execute_shell(s)
    cli.writelog(r)
    # cli.writelog('sleeping for 2 seconds.')
    print('wait..')
    cli.execute_shell('sleep 2')
    i = IP.rindex('.')
    ipparts = IP[0:i]

    # stop dnsmasq if already running.
    if cli.is_process_running('dnsmasq') > 0:
        print('stopping dnsmasq')
        cli.execute_shell('killall dnsmasq')

    # stop hostapd if already running.
    if cli.is_process_running('hostapd') > 0:
        print('stopping hostapd')
        cli.execute_shell('killall hostapd')

    # enable forwarding in sysctl.
    print('enabling forward in sysctl.')
    r = cli.set_sysctl('net.ipv4.ip_forward', '1')
    print(r.strip())

    # enable forwarding in iptables.
    print('creating NAT using iptables: ' + wlan + '<->' + ppp)
    cli.execute_shell('iptables -P FORWARD ACCEPT')

    # add iptables rules to create the NAT.
    cli.execute_shell('iptables --table nat --delete-chain')
    cli.execute_shell('iptables --table nat -F')
    r = cli.execute_shell('iptables --table nat -X')
    if len(r.strip()) > 0: print(r.strip())
    cli.execute_shell('iptables -t nat -A POSTROUTING -o ' + ppp + ' -j MASQUERADE')
    cli.execute_shell(
        'iptables -A FORWARD -i ' + ppp + ' -o ' + wlan + ' -j ACCEPT -m state --state RELATED,ESTABLISHED')
    cli.execute_shell('iptables -A FORWARD -i ' + wlan + ' -o ' + ppp + ' -j ACCEPT')

    # allow traffic to/from wlan
    cli.execute_shell('iptables -A OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
    cli.execute_shell('iptables -A INPUT --in-interface ' + wlan + ' -j ACCEPT')

    # start dnsmasq
    s = 'dnsmasq --dhcp-authoritative --interface=' + wlan + ' --dhcp-range=' + ipparts + '.20,' + ipparts + '.100,' + netmask + ',4h'
    print('running dnsmasq')
    print(s)
    r = cli.execute_shell(s)
    cli.writelog(r)

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
    s = 'hostapd -B {}'.format(run_conf)
    print(s)
    cli.writelog('running hostapd')
    # cli.writelog('sleeping for 2 seconds.')
    cli.writelog('wait..')
    cli.execute_shell('sleep 2')
    r = cli.execute_shell(s)
    cli.writelog(r)
    print('hotspot is running.')
    return


def stop_router():
    # bring down the interface
    cli.execute_shell('ifconfig mon.' + wlan + ' down')

    # TODO: Find some workaround. killing hostapd brings down the wlan0 interface in ifconfig.
    # ~ #stop hostapd
    # ~ if cli.is_process_running('hostapd')>0:
    # ~ cli.writelog('stopping hostapd')
    # ~ cli.execute_shell('pkill hostapd')

    # stop dnsmasq
    if cli.is_process_running('dnsmasq') > 0:
        cli.writelog('stopping dnsmasq')
        cli.execute_shell('killall dnsmasq')

    # disable forwarding in iptables.
    cli.writelog('disabling forward rules in iptables.')
    cli.execute_shell('iptables -P FORWARD DROP')

    # delete iptables rules that were added for wlan traffic.
    if wlan != None:
        cli.execute_shell('iptables -D OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
        cli.execute_shell('iptables -D INPUT --in-interface ' + wlan + ' -j ACCEPT')
    cli.execute_shell('iptables --table nat --delete-chain')
    cli.execute_shell('iptables --table nat -F')
    cli.execute_shell('iptables --table nat -X')
    # disable forwarding in sysctl.
    cli.writelog('disabling forward in sysctl.')
    r = cli.set_sysctl('net.ipv4.ip_forward', '0')
    print(r.strip())
    # cli.execute_shell('ifconfig ' + wlan + ' down'  + IP + ' netmask ' + Netmask)
    # cli.execute_shell('ip addr flush ' + wlan)
    print('hotspot has stopped.')
    return


def main(args):
    global wlan, ppp, IP, netmask
    the_version = open("VERSION").read().strip()
    print("****")
    print("Hotspotd " + the_version)
    print("A simple daemon to create wifi hotspot on Linux!")
    print("****")
    print("Copyright (c) 2014-2016")
    print("Prahlad Yeri<prahladyeri@yahoo.com>\n")

    scpath = os.path.realpath(__file__)
    realdir = os.path.dirname(scpath)
    os.chdir(realdir)
    # print 'changed directory to ' + os.path.dirname(scpath)
    # if an instance is already running, then quit
    # const.verbose = args.verbose
    # const.command = args.command
    # const.blocking = args.blocking
    # const.argv = [os.getcwd() + '/server.py'] + sys.argv[1:]
    cli.arguments = args  # initialize

    newconfig = False
    if not os.path.exists(args.hotspotd):
        if not configure(args.hotspotd, args.run_conf):
            return
        newconfig = True
    if len(cli.check_sysfile('hostapd')) == 0:
        print(
            "hostapd is not installed on your system. This package will not work without it.\nTo install hostapd, run 'sudo apt-get install hostapd'\nor refer to http://wireless.kernel.org/en/users/Documentation/hostapd after this installation gets over.")
        time.sleep(2)
    try:
        with open(args.hotspotd) as hotspotd_file:
            dc = json.load(hotspotd_file)
        wlan = dc['wlan']
        ppp = dc['inet']
        IP = dc['ip']
        netmask = dc['netmask']
        SSID = dc['SSID']
        password = dc['password']
    except:
        print("Error loadind {}".format(args.hotspotd))
        if not configure(args.hotspotd, args.run_conf):
            return
        newconfig = True

    if args.command == 'configure':
        if not newconfig:
            if not configure(args.hotspotd, args.run_conf):
                return
    elif args.command == 'stop':
        stop_router()
    elif args.command == 'start':
        if (cli.is_process_running('hostapd') != 0 and cli.is_process_running('dnsmasq') != 0):
            print('hotspot is already running.')
        else:
            start_router(args.run_conf)
