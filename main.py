from multiprocessing import Process
from DNS_Scanner import dns_capture
from VT_Domain_Scanner_py3 import vt_lookup
import time
import config
import logging

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        level=logging.INFO,
                        filename='maldns.log',
                        datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("Starting DNS Traffic Capture")

    dns_scan = Process(target = dns_capture, args=())
    dns_scan.start()

    time.sleep(1)

    if dns_scan.is_alive():
        logging.info("Starting VirusTotal Scan")
        vt_scan = Process(target = vt_lookup, args=())
        vt_scan.start()

