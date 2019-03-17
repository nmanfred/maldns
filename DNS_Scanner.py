import pyshark
import netifaces
import sys
import datetime
import os
from db_utils import create_connection, create_table


def is_subdomain_in_domain_list(subdomain, domain_list):
    return any(map((lambda x: subdomain.endswith(x) and len(x) > 0), domain_list))


def is_whitelisted(domain):
    """ Determine if a domain is whitelisted
    :param domain: A domain (unsanitized)
    :return: True if domain is whitelisted, False otherwise
    """
    for filename in os.listdir('./domain-list/data/'):
        # For now, all data files from submodule except nsa are WLd
        if filename != 'nsa':
            fn = "./domain-list/data/{}".format(filename)
            with open(fn, "r") as f:
                wl_domain_list = f.read().splitlines()
                # check if any in whitelist end domain, 
                # if so, consider domain whitelisted
                if is_subdomain_in_domain_list(domain, wl_domain_list):
                        print("Domain {} is whitelisted.".format(domain.replace('.', '[.]')))
                        return True
    return False


def is_blacklisted(domain):
    """ Determine if a domain is blacklisted
    :param domain: A domain (unsanitized)
    :return: True if domain is blacklisted, False otherwise
    """
    # For now, only nsa is our BL
    # Let's let VT scan the malware domains, and use this just to catch
    # domains that may be clean on VT but are known to be associated with the NSA
    with open('./domain-list/data/nsa', "r") as f:
        bl_domain_list = f.read().splitlines()
        # check if any in blacklist end in domain, 
        # if so, consider domain blacklisted
        if is_subdomain_in_domain_list(domain, bl_domain_list):
            print("Domain {} is NSA.".format(domain.replace('.', '[.]')))
            return True
        else:
            return False


def store_dns_info(pkt, conn):
    """ Grab DNS query URLs and store them in the dns_queries table
    :param pkt: A packet 
    :return:
    """
    qry_name = pkt.dns.qry_name
    # sanitize domain in database for safety
    qry_sani = pkt.dns.qry_name.replace('.', '[.]')
    try:
        if qry_name:
            c = conn.cursor()
            c.execute('SELECT * FROM dns_queries WHERE url=?;', (qry_sani,) )
            entry = c.fetchone()

            if entry is None:
                # insert blacklisted domains as known bad
                if is_blacklisted(qry_name):
                    c.execute('INSERT INTO dns_queries(last_scan, url, num_positive, total_scans) VALUES (?, ?, ?, ?);', (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), qry_sani, 9001, 0))
                    conn.commit()
                # insert non-whitelisted domains to scan
                elif not is_whitelisted(qry_name):
                    c.execute('INSERT INTO dns_queries(url) VALUES (?);', (qry_sani,))
                    conn.commit()
            c.close()
    except Exception as e:
        print('Exception {}:'.format(e))


def dns_capture():
    conn = create_connection("./maldns.db")
    if conn == None:
        sys.exit(1)

    create_table(conn)

    interface = ''
    with open('interface.conf', 'r', newline='') as f:
        interface = f.read().strip()

    if interface not in netifaces.interfaces():
        print("Bad interface. Check interface.conf")
        sys.exit(1)

    cap = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 53')

    for pkt in cap.sniff_continuously():
        store_dns_info(pkt, conn)

    conn.close()
