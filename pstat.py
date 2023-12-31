#!/usr/bin/env python3

import socket
from socket import AF_INET
from socket import SOCK_DGRAM
from socket import SOCK_STREAM
from functools import lru_cache

import psutil
import requests
import pyuac
import hashlib
import pyfiglet
import threading
import os
import sys
import traceback
import yaml
import datetime
import json
import logging

logging.basicConfig(filename="pstat.log", level=logging.DEBUG)

AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

GEOIP_WHITELIST_ZONES = []

GEOIP_REDLIST_ZONES = []

WHITELISTED_APPS = []

PRIVATE_IP = []

VIRUSTOTAL_API_KEY = ""

PROCESS_LIST = []

def load_yaml_configs():
    global VIRUSTOTAL_API_KEY
    global GEOIP_WHITELIST_ZONES
    global GEOIP_REDLIST_ZONES
    global PRIVATE_IP
    try:
        with open("config.yaml", 'r') as f:
            data = yaml.safe_load(f)
        VIRUSTOTAL_API_KEY = data["VIRUSTOTAL_API_KEY"]
        GEOIP_WHITELIST_ZONES = data["GEOIP_WHITELIST_ZONES"]
        GEOIP_REDLIST_ZONES = data["GEOIP_REDLIST_ZONES"]
        PRIVATE_IP = data["PRIVATE_IP"]
        return True
    except yaml.YAMLError as err:
        logging.error(str(err))
    except KeyError as error:
        logging.error(str(error))
    except ValueError as error:
        logging.error(str(error))


def load_whitelisted_app_list():
    f = open('whitelisted-apps', 'r')
    for x in f:
        WHITELISTED_APPS.append(x.strip())
    return True


VIRUSTOTAL_HASH_RESULTS = {}

@lru_cache
def get_virustotal_analysis(hash):

    if hash in VIRUSTOTAL_HASH_RESULTS.keys():
        return VIRUSTOTAL_HASH_RESULTS[hash]
    else:
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        data = response.json()
        last_analysis = data["data"]["attributes"]["last_analysis_stats"]
        VIRUSTOTAL_HASH_RESULTS[hash] = last_analysis
        return last_analysis


def generate_file_hash(file):
    try:
        h = hashlib.sha256()
        with open(file, 'rb') as f:

            chunk = 0
            while chunk != b'':
                chunk = f.read(1024)
                h.update(chunk)
    except Exception as error:
        print(error)
    return h.hexdigest()

def get_whois_lookup(ip) -> dict:
    r = requests.get(f"https://ipinfo.io/{ip}/json")
    return r.json()



def check_running_processes():
    proc_names = {}
    for p in psutil.process_iter(['pid', 'name']):
        proc_names[p.info['pid']] = p.info['name']
        try:
            process = psutil.Process(p.info['pid'])
            executable_path = process.exe()
            f = open("whitelisted-apps", "a")
            f.write(executable_path + "\n")
            f.close()
        except psutil.AccessDenied:
            pass
    input("Press Enter to Exit...")
    return None


ID = []
IP = []
HASHES = {}

def get_process_stats(dict):
    templ = "%-30s %-10s %-20s %-24s %-10s %-30s"
    try:
        if dict['pid'] in ID and dict["dest_ip"] in IP:
            return None
        elif dict["pid"] in ID and dict["dest_ip"] not in IP:
                    hash = HASHES[dict["name"]]
                    virustotal_results = get_virustotal_analysis(hash)
                    dict["virustotal_analysis"] = virustotal_results
                    ip = dict["dest_ip"].split(":")[0]
                    whois = get_whois_lookup(ip)
                    dict["whois"] = whois
                    dict["hash"] = HASHES[dict["name"]]
                    IP.append(dict["dest_ip"])
                    country = whois['country'] if 'country' in whois else '#N/A'
                    name = dict['name'][0:15] + '...' if len(dict['name']) > 16 else dict['name']
                    print(templ % (str(datetime.datetime.now()), dict['pid'], name, dict['dest_ip'], country, dict['exe_path']))
                    return dict
        else:
            hash = generate_file_hash(dict["exe_path"])
            dict["hash"] = hash
            HASHES[dict["name"]] = hash
            virustotal_results = get_virustotal_analysis(hash)
            dict["virustotal_analysis"] = virustotal_results
            ip = dict["dest_ip"].split(":")[0]
            whois = get_whois_lookup(ip)
            dict["whois"] = whois
            ID.append(dict["pid"])
            IP.append(dict["dest_ip"])
            country = whois['country'] if 'country' in whois else '#N/A'
            name = dict['name'][0:15] + '...' if len(dict['name']) > 16 else dict['name']
            print(templ % (str(datetime.datetime.now()), dict['pid'], name, dict['dest_ip'], country, dict['exe_path']))
            return dict

    except Exception as error:
        traceback.print_exc()
        with open("error.log", "a") as f:
            f.write(str(error))
        return str(error)


def check_net_connections():
    proc_names = {}
    for p in psutil.process_iter(['pid', 'name']):
        proc_names[p.info['pid']] = p.info['name']
    for c in psutil.net_connections(kind='inet4'):
        laddr = "%s:%s" % (c.laddr)
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % (c.raddr)
        name = proc_names.get(c.pid, '?') or ''
        if c.status == "ESTABLISHED":
            ip = raddr.split(":")[0]
            try:
                process = psutil.Process(c.pid)
                path = process.exe()
            except psutil.AccessDenied as error:
                    pass
            if ip.split('.')[0] not in PRIVATE_IP and path not in WHITELISTED_APPS:
                dict = {
                    "protocol": proto_map[(c.family, c.type)],
                    "src_ip": laddr,
                    "dest_ip": raddr or AD,
                    "status": c.status,
                    "pid": c.pid or AD,
                    "name": name,
                    "exe_path" : path,
                    "hostname": socket.gethostname(),
                    "timestamp": str(datetime.datetime.now())
                }
                return dict
    

def main():
    templ = "%-30s %-10s %-20s %-24s %-10s %-30s"
    title = pyfiglet.figlet_format("PSTAT", font='doom')
    print(title)
    print("[+]  Checking for the active TCP/IP and UDP connections......")
    print("[+]  Output File: output.json")
    if load_yaml_configs() and load_whitelisted_app_list():
        print("[+]  Loaded configurations from 'config.yaml'")
        print("[+]  Loaded whitelisted application paths from 'whitelisted-apps' file")
        print("\n")
        print(templ % ("Timestamp", "PID", "Process Name", "Destination IP", "Country", "File Path"))
        while True:
            output = check_net_connections()
            stats = get_process_stats(output)
            if stats:
                    try:
                        with open("output.json", encoding='utf8') as f:
                            file = f.read()
                            data = json.loads(file)
                    except json.JSONDecodeError:
                        data = []
                    except Exception as error:
                        f = open("error.log", 'a')
                        f.write(str(error))
                        f.close()

                    data.append(stats)
                    with open("output.json", 'w', encoding='utf-8') as file:
                        json.dump(data, file, ensure_ascii=False, indent=4)


    else:
        print("Configs are not given")


if __name__ == '__main__':
    try:
        if not pyuac.isUserAdmin():
            print("Launching as admin!")
            pyuac.runAsAdmin()
        else:        
            main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        pass
    except psutil.AccessDenied:
        pass
    finally:
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))