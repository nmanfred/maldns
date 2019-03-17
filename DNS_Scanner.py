import pyshark
import netifaces
import sys
from db_utils import create_connection, create_table


def store_dns_info(pkt, conn):
    """ Grab DNS query URLs and store them in the dns_queries table
    :param pkt: A packet 
    :return:
    """
    qry_name = pkt.dns.qry_name
    try:
        if qry_name:
            c = conn.cursor()
            c.execute('SELECT * FROM dns_queries WHERE url=?;', (qry_name,) )
            entry = c.fetchone()
            # sanitize domain in database for safety
            qry_sani = qry_name.replace('.', '[.]')
            if entry is None: # insert new entry
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
