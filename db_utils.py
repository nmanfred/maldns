import sqlite3
from sqlite3 import Error


def create_connection(db_file):
    """ create a database connection to SQLite database 
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return None

def create_table(conn):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :return:
    """

    create_table_sql = """ CREATE TABLE IF NOT EXISTS dns_queries (
        id integer PRIMARY KEY,
        last_scan text,
        url text NOT NULL,
        num_positive integer,
        total_scans integer,
        permalink text
    ); """

    c = conn.cursor()
    c.execute(create_table_sql)
