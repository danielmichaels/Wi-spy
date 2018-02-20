#!/usr/bin/env python3

from contextlib import closing
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
import sys
import datetime
import sqlite3

# Import config
from config import *


# TODO: only log changes - enter/ exit range (if gone for x time, log as exit)
# TODO: only show unique entries.
# TODO: auto generate databases instead of hardcoding.
# TODO: use dict so MAC can have value associated with it.


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
                print('report should fire.')
                msg = 'alive'
                report(None, mac, msg, timestamp)

            printer(mac, rssi, timestamp, ssid)
            log(ssid, mac, rssi, timestamp)


def get_rssi(packet):
    """Gets the RSSI of packet from RadioTap"""
    if packet.haslayer(RadioTap):
        return packet.dbm_antsignal


def epoch():
    """Get local time."""
    dt = datetime.datetime.utcnow()
    epoch = datetime.datetime.timestamp(dt)
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
    with closing(sqlite3.connect('probe_logs.db')) as cursor:
        cursor.execute(
            "INSERT OR IGNORE INTO probes VALUES (:ssid, :mac, :rssi, :epoch);",
            dict(ssid=ssid, mac=mac, rssi=rssi, epoch=epoch))
        cursor.commit()


def report(target, mac, timestamp, msg):
    """Alert if specified MAC is in range."""
    with closing(sqlite3.connect('report_log.db')) as cursor:
        cursor.execute("""INSERT INTO report VALUES(:target,
                       :mac, :timestamp, :msg);""",
                       dict(target=target, mac=mac,
                            timestamp=timestamp, msg=msg))
        cursor.commit()


def create_db():
    """Creates db. Callback within log()."""
    with sqlite3.connect('probe_logs.db') as conn:
        with closing(conn.cursor()) as cursor:
            create_probe_table = """CREATE TABLE IF NOT EXISTS probes(
        ssid TEXT, mac TEXT, rssi TEXT, epoch TEXT)"""
            cursor.execute(create_probe_table)
            conn.commit()

    with sqlite3.connect('report_log.db') as conn:
        with closing(conn.cursor()) as cursor:
            create_report_table = """CREATE TABlE IF NOT EXISTS report(
            target TEXT, mac TEXT, msg TEXT, timestamp TEXT)"""
            cursor.execute(create_report_table)
            conn.commit()


def main():
    """Setup function."""
    create_db()  # check for db, or create it.


if __name__ == '__main__':
    main()
    for_testing_only = list()
    # sniff(iface=sys.argv[1], store=0, prn=packet_handler)
    sniff(iface=IFACE, store=0, prn=packet_handler)
