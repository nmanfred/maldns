from multiprocessing import Process
from DNS_Scanner import dns_capture
from VT_Domain_Scanner_py3 import vt_lookup
import time
import config
import logging

if __name__ == '__main__':
    logging.basicConfig(filename='maldns.log', level=logging.INFO)
    logging.info("Starting DNS Traffic Capture")
    dns_scan = Process(target = dns_capture, args=())
    dns_scan.start()

    time.sleep(1)

    logging.info("Starting VirusTotal Scan")
    vt_scan = Process(target = vt_lookup, args=())
    vt_scan.start()
