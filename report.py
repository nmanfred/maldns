from db_utils import create_connection
import argparse

if __name__== "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dump-all", help="Dump the whole database",
                    action="store_true")
    group.add_argument("--dump-flagged", help="Dump entries flagged by VirusTotal as having at least one bad report",
                    action="store_true")
    group.add_argument("--dump-nsa", help="Dump domains associated with the NSA",
                    action="store_true")
    args = parser.parse_args()

    conn = create_connection("./maldns.db")
    if conn == None:
        print ("No database connection, exiting.")
        sys.exit(1)

    c = conn.cursor()
    c.execute('SELECT * FROM dns_queries;')
    rows = c.fetchall()
    
    if args.dump_all:
       print("ID Time Domain NumFlagged NumTested VirusTotalLink")
       for row in rows:
           print("{} {} {} {} {} {}".format(row[0],row[1],row[2],row[3],row[4],row[5]))
    elif args.dump_flagged:
       print("ID Time Domain NumFlagged NumTested VirusTotalLink")
       for row in rows:
           if row[3] > 0: #NumFlagged
               print("{} {} {} {} {} {}".format(row[0],row[1],row[2],row[3],row[4],row[5]))
    elif args.dump_nsa:
       print("ID Time Domain NumFlagged NumTested VirusTotalLink")
       for row in rows:
           if row[3] > 9000: #NumFlagged
               print("{} {} {} {} {} {}".format(row[0],row[1],row[2],row[3],row[4],row[5]))
    else:
       parser.print_help()

    c.close()

