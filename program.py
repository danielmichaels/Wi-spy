#!/usr/bin/env python3

from contextlib import closing
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
from datetime import datetime, timedelta
import sqlite3

# Import config
from config import *
# Import database
from database import SqlDatabase


# Globals
Query = collections.namedtuple('query', 'target mac msg time debug')
db = SqlDatabase('test.db') # database for logging targets.


# TODO: auto generate databases instead of hardcoding.
# TODO: use dict so MAC can have value associated with it.
# TODO: current sql query only returns last report. needs to return last of
# TODO: ^cont. each target in list.
# TODO: should I return constant 'alive' & 'dead' or make conditional?
# TODO: target that sleeps doesn't probe until in use --> force it.


def packet_handler(packet):
    """Sniff for ProbeAssoReq, ReassoReq and Probrequest.
    Display results to screen
    """
    management_frames = (0, 2, 4)
    timestamp = epoch()

    rssi = get_rssi(packet)

    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype in management_frames:
            ssid = packet.info
            mac = packet.addr2
            if mac in TARGET_LIST:
                try:
                    print('report should fire.', timestamp, mac,
                          epoch_to_local(timestamp))
                    report(None, mac, 'alive', timestamp,
                           epoch_to_local(timestamp))
                    time.sleep(5)  # to stop multiple entries
                except TypeError as te:
                    print('we have an error:', te)

            if timestamp > (query.time + ALERT_THRESHOLD):
                try:
                    print('report should return dead for: {}'.format(
                        query().mac), epoch_to_local(timestamp))

                    report(query.target, query().mac,
                           'Dead', query().time,
                           epoch_to_local(timestamp))
                    time.sleep(5)  # to stop multiple entries
                except TypeError as te:
                    print('we have an error:', te)

            printer(mac, rssi, timestamp, ssid)
            log(ssid, mac, rssi, timestamp)


def get_rssi(packet):
    """Gets the RSSI of packet from RadioTap"""
    if packet.haslayer(RadioTap):
        return packet.dbm_antsignal


def epoch():
    """Get local time."""
    dt = datetime.utcnow()
    epoch = int(datetime.timestamp(dt))
    return epoch


def epoch_to_local(epoch):
    """Return the epoch time in system time. Human readability paramount."""
    return time.ctime(epoch)


def printer(mac, rssi, timestamp, ssid):
    # print("MAC: {}      RSSI: {}        TIME: {}    PROBES: {}".format(
    # mac, rssi, epoch_to_local(timestamp), ssid))
    """All below for testing only. Remove when done."""
    if mac not in for_testing_only:
        for_testing_only.append(mac)
        print("MAC: {}      RSSI: {}        TIME: {}    PROBES: {}".format(
            mac, rssi, epoch_to_local(timestamp), ssid))



def log(ssid, mac, rssi, epoch):
    """Log packets to database"""
    pass


def report(target, mac, timestamp, msg, debug):
    """Alert if specified MAC is in range."""
    pass

if __name__ == '__main__':

    for_testing_only = list()
    # sniff(iface=sys.argv[1], store=0, prn=packet_handler)
    sniff(iface=IFACE, store=0, prn=packet_handler)
