from contextlib import closing
import sqlite3

# import config
from config import *


class SqlDatabase:

    def __init__(self, name=None):

        if name:
            self.open(name)

    def open(self, name):
        try:
            self.conn = sqlite3.connect(name)
            self.cursor = self.conn.cursor()

        except sqlite3.Error as e:
            print("Error opening Database: {}".format(name))
            # log?

    def get(self, table, column, limit=None):

        query = "SELECT {0} from {1};".format(column, table)
        self.cursor.execute(query)

        # fetch data
        rows = self.cursor.fetchall()

        return rows[len(rows) - limit if limit else 0:]

    def get_last(self, table, column):

        return self.get(table, column, limit=1)[0]

    def write(self, table, column, *data):
        query = "INSERT INTO {0} ({1}) VALUES ({2});".format(
            table, column, *data)
        self.cursor.execute(query)

    def query(self, *sql):
        """Enter any other query"""
        self.cursor.execute(*sql)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()

        if isinstance(exc_val, Exception):
            self.conn.rollback()
        else:
            self.conn.commit()

        self.conn.close()


db = SqlDatabase('log.db')

with db:
    a = db.get('messages', '*')
    print(a)
    b = db.get_last('messages', '*')
    print(b)
    db.write('messages', 'lvl', 'adfa', )
    # db.query("""insert into messages values(:dtg, :lvl, :msg);""",
    #     dict(dtg='1214241', lvl='dafda', msg='working?'))
