from multiprocessing import Process
from DNS_Scanner import dns_capture
from VT_Domain_Scanner_py3 import vt_lookup
import time
import config

if __name__ == '__main__':

    print("Starting DNS Traffic Capture")
    dns_scan = Process(target = dns_capture, args=())
    dns_scan.start()

    time.sleep(1)

    print("Starting VirusTotal Scan")
    vt_scan = Process(target = vt_lookup, args=())
    vt_scan.start()
