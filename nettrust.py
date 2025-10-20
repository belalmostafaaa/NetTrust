#!/usr/bin/env python3

import argparse
import json
import os
import time
import socket
import subprocess
from typing import Dict, List
import re
from collections import defaultdict

# made by my previous ASCII designer CLI Tool
BANNER = "\033[36m" + r"""
 __  __          __    ______                        __      
/\ \/\ \        /\ \__/\__  _\                      /\ \__   
\ \ `\\ \     __\ \ ,_\/_/\ \/ _ __   __  __    ____\ \ ,_\  
 \ \ , ` \  /'__`\ \ \/  \ \ \/\`'__\/\ \/\ \  /',__\\ \ \/  
  \ \ \`\ \/\  __/\ \ \_  \ \ \ \ \/ \ \ \_\ \/\__, `\\ \ \_ 
   \ \_\ \_\ \____\\ \__\  \ \_\ \_\  \ \____/\/\____/ \ \__
    \/_/\/_/\/____/ \/__/   \/_/\/_/   \/___/  \/___/   \/__/
""" + "\033[0m"

print(BANNER)

# Tried scapy first, but had to fallback to nmap when it bombed—saved my sanity!
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("No scapy? No sweat, using nmap as a backup plan.")

import networkx as nx
from termcolor import colored


CONF_DIR = os.path.expanduser("~/.nettrust")
CONF_FILE = os.path.join(CONF_DIR, "settings.json")
ALERT_LOG = os.path.join(os.path.dirname(__file__), "alerts.log")  # Keeps logs handy

def make_setup_dir():  # Renamed, took a few tries to get permissions right
    if not os.path.exists(CONF_DIR):
        os.makedirs(CONF_DIR)

def write_log(msg):  
    with open(ALERT_LOG, 'a') as f:
        f.write(f"{time.ctime()}: {msg}\n")
    print(msg)

def clean_ansi(text):  # My way of stripping colors, worked after some regex fun
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\a', '', text)

def load_settings(): 
    make_setup_dir()
    if os.path.exists(CONF_FILE):
        with open(CONF_FILE, 'r') as f:
            return json.load(f)
    return {"safe_list": {}, "net_scope": "192.168.1.0/24"}  # Default I use at home

def save_settings(conf):
    with open(CONF_FILE, 'w') as f:
        json.dump(conf, f, indent=4)  # Indent so I can read it later

def do_scan(ip_range):  
    found_devs = {}
    if SCAPY_OK:
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=3, verbose=0)
            for _, resp in ans:
                found_devs[resp.psrc] = resp.hwsrc
        except PermissionError:
            print(colored("Oops, need root or cap_net_raw for scapy. Try sudo!", "red"))
            exit(1)
    else:
        try:
            res = subprocess.check_output(["nmap", "-sn", ip_range]).decode()
            for line in res.splitlines():
                if "Nmap scan report for" in line:
                    ip = line.split()[-1].strip("()")
                elif "MAC Address:" in line:
                    mac = line.split()[2]
                    found_devs[ip] = mac
        except FileNotFoundError:
            print(colored("Yikes, need scapy or nmap installed!", "red"))
            exit(1)
    return found_devs

def build_net_graph(devs, trusted):
    G = nx.Graph()
    gate = socket.gethostbyname(socket.gethostname())  # Guessed this, works most times
    G.add_node(gate, label="Gateway (Guess)", type="gateway")
    for ip, mac in devs.items():
        name = trusted.get(ip, {}).get("name", "Unknown Guy")
        trust_mac = trusted.get(ip, {}).get("mac", None)
        is_trusted = ip in trusted and (trust_mac is None or trust_mac == mac)
        label = f"{name} ({ip}/{mac})"
        G.add_node(ip, label=label, trusted=is_trusted)
        G.add_edge(gate, ip)
    return G

def draw_graph(G): 
    def draw_node(n, indent="", last=True):
        lines = []
        pref = indent + ("└── " if last else "├── ")
        lbl = G.nodes[n]["label"]
        trust = G.nodes.get(n, {}).get("trusted", False)
        col = "green" if trust else "red"
        bold_lbl = colored(lbl, col, attrs=["bold"])
        lines.append(pref + bold_lbl)
        kids = list(G.neighbors(n))
        for i, kid in enumerate(kids):
            G.remove_edge(n, kid)  # Fixed loops after some debugging headaches!
            lines.extend(draw_node(kid, indent + ("    " if last else "│   "), i == len(kids) - 1))
        return lines

    root = next(n for n in G if G.nodes[n].get("type") == "gateway")
    return "\n".join(draw_node(root))

def check_alerts(devs, trusted, talkative=False):  
    sketchy = []
    for ip, mac in devs.items():
        if ip not in trusted or (trusted[ip].get("mac") and trusted[ip]["mac"] != mac):
            sketchy.append(f"{ip}/{mac}")
    if sketchy:
        alert = colored(f"ALERT: Sketchy devices: {', '.join(sketchy)}", "red", attrs=["bold"])
        write_log(alert + "\a")
    else:
        all_good = colored("All chill, no intruders.", "green", attrs=["bold"])
        if talkative:
            write_log(all_good)
    return sketchy

def make_report(out_file):
    if not os.path.exists(ALERT_LOG):
        print(colored("No log file yet, run monitor first!", "yellow"))
        return

    data = defaultdict(list)
    with open(ALERT_LOG, 'r') as f:
        for line in f:
            if ':' not in line:
                continue
            t_stamp, msg = line.split(':', 1)
            t_stamp = t_stamp.strip()
            clean_msg = clean_ansi(msg.strip())
            if "ALERT: Sketchy devices:" in clean_msg:
                dev_str = clean_msg.split("Sketchy devices: ")[1].strip()
                devs = [d.strip() for d in dev_str.split(",")]
                for dev in devs:
                    data[dev].append(t_stamp)

    if not data:
        print(colored("No sketchy devices logged.", "yellow"))
        return

    with open(out_file, 'w') as f:
        for dev, times in sorted(data.items()):
            f.write(f"{dev}: {', '.join(sorted(set(times)))}\n")

    print(colored(f"Report done at: {out_file}", "green"))

def main():
    parser = argparse.ArgumentParser(
        description="NetTrustViz: My hacked-together net trust checker. Handles safe devices, scans, bg monitoring, and log reports.",
        epilog="""Examples:
  Configure trusted devices:
    ./nettrust.py config --add "192.168.1.1:Router:aa:bb:cc:dd:ee:ff" --network "192.168.1.0/24" --list
      Adds a device with IP, name, MAC; sets range; lists trusted.

  Scan the network:
    ./nettrust.py scan --range "192.168.1.0/24" --verbose
      Scans range, shows trust status, ASCII map with extra talk if --verbose.

  Monitor in background:
    nohup ./nettrust.py monitor --interval 60 --range "192.168.1.0/24" >> alerts.log 2>&1 &
      Keeps scanning, logs alerts, runs after terminal close with nohup.

  Generate report:
    ./nettrust.py report --output myreport.txt
      Pulls untrusted from log with times, saves to file.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command")

    # Config parser, added a note from my setup struggles
    config_parser = subparsers.add_parser(
        "config",
        help="Handle trusted devices: add/remove/list/set range.",
        description="Configures your trusted stuff and net settings. Saved in ~/.nettrust/settings.json."
    )
    config_parser.add_argument("--add", help="Add safe device: 'IP:name:mac' (mac optional). Ex: '192.168.1.10:Phone:aa:bb:cc:dd:ee:ff'", type=str)
    config_parser.add_argument("--remove", help="Drop device by IP. Ex: '192.168.1.10'", type=str)
    config_parser.add_argument("--list", action="store_true", help="Show safe devices and range. Run: ./nettrust.py config --list")
    config_parser.add_argument("--network", help="Set range (e.g. '192.168.1.0/24'). Ex: --network '192.168.1.0/24'", type=str)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan net and show topology.",
        description="Quick scan, finds trusted/untrusted, draws ASCII graph with colors."  # Tweaked for variety
    )
    scan_parser.add_argument("--range", help="Range to scan (override config). Ex: --range '192.168.1.0/24'", type=str)
    scan_parser.add_argument("--verbose", action="store_true", help="More output, like 'all good' if safe. Run: ./nettrust.py scan --verbose")

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Bg monitor with scans/alerts.",
        description="Loops scans, logs to alerts.log. Use nohup to keep it alive."  # Casual note
    )
    monitor_parser.add_argument("--interval", help="Interval secs (def 300). Ex: --interval 60", type=int, default=300)
    monitor_parser.add_argument("--range", help="Range to monitor (override). Ex: --range '192.168.1.0/24'", type=str)

    report_parser = subparsers.add_parser(
        "report",
        help="Report untrusted from alerts.log.",
        description="Grabs unique untrusted with times from log, to text file."
    )
    report_parser.add_argument("--output", help="Output file (def untrusted_report.txt). Ex: --output myreport.txt", type=str, default="untrusted_report.txt")

    args = parser.parse_args()
    setup = load_settings()  

    if args.command == "config":
        if args.add:
            parts = args.add.split(":")
            ip = parts[0]
            name = parts[1] if len(parts) > 1 else "Unnamed"
            mac = parts[2] if len(parts) > 2 else None
            setup["safe_list"][ip] = {"name": name, "mac": mac}
        if args.remove:
            setup["safe_list"].pop(args.remove, None)
        if args.network:
            setup["net_scope"] = args.network
        save_settings(setup)
        if args.list:
            for ip, info in setup["safe_list"].items():
                print(f"{ip}: {info['name']} (MAC: {info.get('mac', 'Any')})")
            print(f"Network Scope: {setup['net_scope']}")
            print(f"Logs at: {ALERT_LOG}")

    elif args.command == "scan":
        ip_range = args.range or setup["net_scope"]
        devices = do_scan(ip_range)
        check_alerts(devices, setup["safe_list"], args.verbose)
        graph = build_net_graph(devices, setup["safe_list"])
        print("Network Map:")
        print(draw_graph(graph))

    elif args.command == "monitor":
        ip_range = args.range or setup["net_scope"]
        start_msg = colored(f"Monitoring {ip_range} every {args.interval}s. Logs to {ALERT_LOG}", "yellow")
        write_log(start_msg)
        print(f"Run bg with: nohup ./nettrust.py monitor --interval {args.interval} >> {ALERT_LOG} 2>&1 &")
        while True:
            devices = do_scan(ip_range)
            write_log(f"Scan done. {len(devices)} devices: {list(devices.keys())}")
            check_alerts(devices, setup["safe_list"])
            time.sleep(args.interval)

    elif args.command == "report":
        make_report(args.output)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()