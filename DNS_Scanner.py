import pyshark
import netifaces
import sys
from db_utils import create_connection, create_table


def store_dns_info(pkt):
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

            if entry is None: # insert new entry
                c.execute('INSERT INTO dns_queries(url) VALUES (?);', (qry_name,))
                conn.commit()
    except sqlite3.Error as e:
        print('entry_get_id() Error %s:' % e.args[0])


if __name__ == '__main__':
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

    cap.apply_on_packets(store_dns_info, timeout=100)

    conn.close()










