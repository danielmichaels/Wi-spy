#!/usr/bin/env python3

from contextlib import closing
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
from datetime import datetime, timedelta
import sqlite3

# Import config
from config import *

# Globals
Query = collections.namedtuple('query', 'target mac msg time')


# TODO: auto generate databases instead of hardcoding.
# TODO: use dict so MAC can have value associated with it.
# TODO: current sql query only returns last report. needs to return last of
# TODO: ^cont. each target in list.
# TODO: should I return constant 'alive' & 'dead' or make conditional?
# TODO: put all sql into new file


def packet_handler(packet):
    """Sniff for ProbeAssoReq, ReassoReq and Probrequest.
    Display results to screen
    """
    management_frames = (0, 2, 4)
    timestamp = epoch()
    query = check_if_alive()

    rssi = get_rssi(packet)

    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype in management_frames:
            ssid = packet.info
            mac = packet.addr2
            if mac in TARGET_LIST:
                print('report should fire.', timestamp, mac,
                      epoch_to_local(timestamp))
                report(None, mac, 'alive', timestamp)
                time.sleep(5)  # to stop multiple entries

            if timestamp > (query.time + ALERT_THRESHOLD):
                print('report should return dead for: {}'.format(
                    check_if_alive().mac), epoch_to_local(timestamp))
                report(check_if_alive().target, check_if_alive().mac,
                       'Dead', check_if_alive().time)
                time.sleep(5)  # to stop multiple entries

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


def check_if_alive():
    """Check if the target is no longer in the area."""
    with closing(sqlite3.connect('report_log.db')) as cursor:
        query = cursor.execute(
            'SELECT * FROM report ORDER BY ROWID DESC LIMIT 1;')
        target, mac, msg, time = query.fetchone()
        fetched_query = Query(target=target, mac=mac, msg=msg, time=int(time))
        return fetched_query
        # return target, mac, msg, time


if __name__ == '__main__':
    create_db()  # check for db, or create it.
    for_testing_only = list()
    # sniff(iface=sys.argv[1], store=0, prn=packet_handler)
    sniff(iface=IFACE, store=0, prn=packet_handler)
