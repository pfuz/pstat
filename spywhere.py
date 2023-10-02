#!/usr/bin/env python3

import socket
from socket import AF_INET
from socket import SOCK_DGRAM
from socket import SOCK_STREAM

import psutil
import requests
import logging
import pyuac
import time
import whois
import hashlib

AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

PRIVATE_IP = ["10", "172", "198", "127"]

VIRUSTOTAL_API_KEY = "5df8d97dd0dc875d1caa23c90ad77f4c6382094c94449f0b3dec654c0b8d44a4"

WHITELISTED_APPS = [
    "C:\Windows\System32\svchost.exe",
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
]

def generate_file_hash(path):

    return 

def main():
    print('''\tSpywhere V0.0''')
    logging.info("Checking for the active TCP/UDP connections......")
    print("\n")
    print("\n")
    print("\n")
    # templ = "%-5s %-30s %-30s %-13s %-6s %s"
    # print(templ % (
    #     "Proto", "Local address", "Remote address", "Status", "PID",
    #     "Program name"))
    proc_names = {}
    for p in psutil.process_iter(['pid', 'name']):
        proc_names[p.info['pid']] = p.info['name']
    for c in psutil.net_connections(kind='inet'):
        laddr = "%s:%s" % (c.laddr)
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % (c.raddr)
        name = proc_names.get(c.pid, '?') or ''
        if c.status == "ESTABLISHED":
            ip = raddr.split(":")[0]
            if ip.split('.')[0] not in PRIVATE_IP:
                # r = requests.get(f"http://ipwho.is/{ip}")
                # data = r.json()
                # print(data)
                process = psutil.Process(c.pid)
                path = process.exe()

                print(f"Protocol: {proto_map[(c.family, c.type)]}")
                print(f"Source IP: {laddr}")
                print(f"Destination IP: {raddr or AD}")
                print(f"Status: {c.status}")
                print(f"PID: {c.pid or AD}")
                print(f"Name: {name}")
                print(f"Location: {path}")
                print("Repuation: Trusted") if path in WHITELISTED_APPS else print("Repuatation: Unknown")
                print("###########################################")
    input("Press Enter to Exit...")
            # print(type(r.json()))
        # print(templ % (
        #     proto_map[(c.family, c.type)],
        #     laddr,
        #     raddr or AD,
        #     c.status,
        #     c.pid or AD,
        #     name,
        # ))


if __name__ == '__main__':
    try:
        if not pyuac.isUserAdmin():
            print("Re-launching as admin!")
            pyuac.runAsAdmin()
        else:        
            main()
    except psutil.AccessDenied as exec:
        print(exec)