# program.py
# !/usr/bin/env python3
"""Library for scanning wireless frames and locating MAC addresses of interest.

Using a wireless adapter capable of monitor mode and super user permissions
the library can search for a selection of MAC addresses and log their presence
or absence with both epoch and local system time to a sqlite database.

User must have sudo and aircrack-ng suite to monitor and cycle channels.
"""

from contextlib import closing
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
from datetime import datetime, timedelta

# Import config
from config import *
# Import database
from database import SqlDatabase

# Globals
db = SqlDatabase('test.db')  # database for logging targets.
db.create_table()


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

    if not packet.haslayer(Dot11):
        return

    if packet.type == 0 and packet.subtype in management_frames:

        ssid = packet.info
        mac = packet.addr2
        rssi = get_rssi(packet)
        epoch = epochtime()
        dtg = system_time(epoch)
        msg = None

        print(check_status())

        if mac in TARGET_LIST:
            try:
                print('{} {} {} {} {msg}'.format(mac, rssi, epoch, dtg,
                                                 msg='Alive'))
                report(target=None, mac=mac, rssi=rssi, epoch=epoch,
                       dtg=dtg, msg='Alive')
                time.sleep(5)  # to stop multiple entries
            except TypeError as e:
                print(e)

    # if timestamp > (query.time + ALERT_THRESHOLD):
    #     try:
    #         print('report should return dead for: {}'.format(
    #             query().mac), epoch_to_local(timestamp))
    #
    #         report(query.target, query().mac,
    #                'Dead', query().time,
    #                epoch_to_local(timestamp))
    #         time.sleep(5)  # to stop multiple entries
    #     except TypeError as te:
    #         print('we have an error:', te)

    # printer(mac, rssi, timestamp, ssid)
    # log(ssid, mac, rssi, timestamp)


def get_rssi(packet):
    """Gets the RSSI of packet from RadioTap"""
    if packet.haslayer(RadioTap):
        return packet.dbm_antsignal


def epochtime():
    """Get local time."""
    dt = datetime.utcnow()
    epoch = int(datetime.timestamp(dt))
    return epoch


def system_time(epoch):
    """Return the epoch time in system time. Human readability paramount."""
    return time.ctime(epoch)


def check_status():
    return db.get_last('logging', 'epoch')


def report(target=None, mac=None, rssi=None, epoch=None, dtg=None,
           msg=None):
    """Alert if specified MAC is in range."""
    with closing(SqlDatabase('test.db')) as db:
        db.write(target, mac, rssi, epoch, dtg, msg)


if __name__ == '__main__':
    # sniff(iface=sys.argv[1], store=0, prn=packet_handler)
    sniff(iface=IFACE, store=0, prn=packet_handler)
