from multiprocessing import Process
from DNS_Scanner import dns_capture
from VT_Domain_Scanner_py3 import vt_lookup

if __name__ == '__main__':
    dns_scan = Process(target = dns_capture, args=())
    dns_scan.start()

    #vt_scan = Process(target = vt_lookup, args=())
