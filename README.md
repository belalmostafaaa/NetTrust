# NetTrust

NetTrust is a CLI tool created with python to enhance your securiy with your network. This is made mainly by adding your network range into the tool and specifying the IPs/mac of every device as trusted devices, and when running the tool, it alerts you when there is untrusted device is connected to your network (any other unspecifyied device). Also, it has a unique feature which can be ran continuously in the background even after closing the terminal, and you can run a report command to gather all the detected devices without a need to take a look in the logs of scanning.

---

## Features

- **Trusted Device Management**: Add, remove, or list trusted devices by IP, name, and optional MAC address. Config is saved locally in a JSON file.
- **Network Scanning**: Discover devices on a specified range (e.g., `192.168.1.0/24`) using Scapy (preferred) or Nmap as a fallback. Visualizes topology with a color-coded ASCII art (green for trusted, red for untrusted).
- **Background Monitoring**: Runs periodic scans, logs results, and alerts on untrusted devices. Keeps going even after you close the terminal with `nohup`.
- **Alerting**: Rings a terminal bell (\a) and logs colored alerts for intrusions, saved to `alerts.log` in the script's directory.
- **Reporting**: Generates a text report of unique untrusted devices with detection times from the logs.

---

## Installation Guide

### Dependencies
NetTrust requires Python 3.6+ and the dependencies listed in `requirements.txt`. Install them with:
pip install -r requirements.txt
textOptional (recommended fallback scanning):
- **nmap**: Install system-wide (not via pip).
  - Linux: `sudo apt install nmap` (Ubuntu/Debian) or `sudo dnf install nmap` (Fedora).
  - macOS: `brew install nmap` (with Homebrew).
  - Windows: Download from [nmap.org](https://nmap.org/download.html) and add to PATH.

For non-root scanning (recommended):
- Linux/macOS: `sudo setcap cap_net_raw+eip $(which python3)`.
- Windows: Run as admin or use WSL (capabilities not supported natively).

### Linux
Install Python if missing: 
```
sudo apt update && sudo apt install python3 python3-pip
```
```
git clone https://github.com/belalmostafaaa/NetTrust.git
```
```
cd nettrust
```
```
pip install -r requirements.txt
```
```
chmod +x nettrust.py
```
```
./nettrust.py --help
```

### macOS
```
brew install python
```
```
git clone https://github.com/belalmostafaaa/NetTrust.git
```
```
cd nettrust
```
```
chmod +x nettrust.py
```
```
pip install -r requirements.txt
```

Test installation: `./nettrust.py config --list` should show defaults without errors.

---

## Usage Guide

Run `./nettrust.py --help` for all options. Commands use subparsers (e.g., `config`, `scan`).
