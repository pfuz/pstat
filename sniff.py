from scapy.all import *
import datetime

pk = sniff(filter="host 34.79.222.182")

count = 1
for p in pk:
    if p.haslayer('IP'):
        print(f"[{count} | {datetime.datetime.now()}]: {p.getlayer('IP').src} ----> {p.getlayer('IP').dst} | {len(p)} bytes")
    else:
        print("<None>")
    count = count + 1
