# Wife-fi
A python command-line tool for tracking when handsets enter/exit my local area.

This is a toy script that does the following:

- sniff WLAN frames for probes
- pull in any frame that has a MAC address according to a target list
- log that frame to a sqlite database with the following columns:
    - MAC, rssi, epochtime, system time, status message
- if handset has not probed in 600 seconds send a report stating its dead

## Requirements

```bash
- Aircrack suite
- chipset capable of monitor mode
- sudo privileges
- scapy
```

## Usage

To use just clone the repo. Before attempting to run the script make sure your chipset is in monitor mode.
For this you will need `sudo` privileges. I use `airmon-ng start <interface>` but manually setting monitor using `iwconfig` will also work.

To run the script call `sudo python program.py`. This will begin sniffing the network traffic for the targeted MAC addresses.
It will not print anything to the screen until it finds one, or a previous entry has exceeded the threshold.

--------

### Todo

This script is pretty hacky and as such there is a lot to improve. 

- auto generate databases instead of hard coding.
- use dict so MAC can have value associated with it.
- target that sleeps doesn't probe until in use --> force it.
- select WHERE mac is target_mac and do a check on last seen.
