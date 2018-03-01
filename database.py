import sqlite3

# import config
from config import *


class SqlDatabase:
    """SQLite3 class wrapper

    Made for use in a 'with' statement.

    Methods include:
    - open
    - create_table
    - get: given a column, table and limit; return a fetchall().
    - get_last: utility to get last row in given table and column.
    - write: specific to the program module.
    - query: utility to pass in any functional sql query.
    - __enter__: allows 'with' statement.
    - __exit__: allows 'with' statement.
    """

    def __init__(self, name=None):

        if name:
            self.open(name)

    def open(self, name):
        try:
            self.conn = sqlite3.connect(name)
            self.cursor = self.conn.cursor()

        except sqlite3.Error:
            print("Error opening Database: {}".format(name))
            # log?

    def create_table(self):
        """Create table; currently hardcoded for use within the program module.
        """
        try:
            query = """CREATE TABLE IF NOT EXISTS logging (target TEXT, 
                    mac TEXT, rssi TEXT, epoch INT, dtg TEXT, msg TEXT)"""
            self.cursor.execute(query)
            self.conn.commit()

        except sqlite3.Error as e:
            print(e.__repr__())

    def get(self, table, column, limit=None):
        """Retrieve items within specified column within table and accepts
        a limit of number of returned rows.

        :param table: name of table to be parsed.
        :param column: column within the table.
        :param limit: number of rows the be returned; default is None.

        :return: all rows unless limit argument is used.
        """

        query = "SELECT {0} from {1};".format(column, table)
        self.cursor.execute(query)

        # fetch data
        rows = self.cursor.fetchall()

        return rows[len(rows) - limit if limit else 0:]

    def get_last(self, table, column):
        """Utility method that gets last row.

        :param table: table to search.
        :param column: specific column to get last row.
        :return last row.
        """

        return self.get(table, column, limit=1)[0]

    def write(self, target=None, mac=None, rssi=None, epoch=None,
              dtg=None, msg=None):
        """Write to the database

        :param target: the human readable name.
        :param mac: the MAC address that matches target.
        :param rssi: received signal strength indicator of target/mac.
        :param epoch: machine readable epoch time.
        :param dtg: date time group --> human readable local system time.
        :param msg: generates a msg for logging the status of target.

        Usage:

            # >>> db = SqlDatabase('example_db.db')
            # >>> db.write(target, mac, rssi, epochtime, dtg)

        each param defaults to None.
        """

        query = """insert into logging values(:target, :mac, :rssi, :epoch, :dtg, :msg)"""
        fields = dict(target=target, mac=mac, rssi=rssi, epoch=epoch,
                      dtg=dtg, msg=msg)
        self.cursor.execute(query, fields)  # execute needs (sql [,parameters])
        # self.conn.commit()

    def query(self, *sql):
        """Utility function to enter any valid SQL query"""
        self.cursor.execute(*sql)
        # self.conn.commit()

    def close(self):
        """Closes the database."""

        if self.conn:
            self.conn.commit()
            self.cursor.close()
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()

        if isinstance(exc_val, Exception):
            self.conn.rollback()
        else:
            self.conn.commit()

        self.conn.close()

# RANDOM TESTING STUFF

# db = SqlDatabase('log.db')
# with db:

# with SqlDatabase('test.db') as db:
#     db.create_table()
#     db.query(
#         "INSERT INTO logging VALUES(:target, :mac, :rssi, :epoch, :dtg,"
#         ":msg);",
#         dict(target='target', mac='mac', rssi='rssi', epoch=123142145,
#              dtg='dtg', msg='msg'))
#     db.write('target', 'mac', 'rssi', 12231, 'dtg', 'msg')
