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

        except sqlite3.Error:
            print("Error opening Database: {}".format(name))
            # log?

    def create_table(self):
        try:
            query = """CREATE TABLE IF NOT EXISTS logging (target TEXT, 
                    mac TEXT, rssi TEXT, epochtime TEXT, dtg TEXT)"""
            self.cursor.execute(query)
            self.conn.commit()

        except sqlite3.Error as e:
            print(e.__repr__())

    def get(self, table, column, limit=None):

        query = "SELECT {0} from {1};".format(column, table)
        self.cursor.execute(query)

        # fetch data
        rows = self.cursor.fetchall()

        return rows[len(rows) - limit if limit else 0:]

    def get_last(self, table, column):

        return self.get(table, column, limit=1)[0]

    def write(self, target=None, mac=None, rssi=None, epochtime=None,
              dtg=None):
        query = """insert into logging values(:target, :mac, :rssi, :epochtime, :dtg)"""
        fields = dict(target=target, mac=mac, rssi=rssi, epochtime=epochtime,
                      dtg=dtg)
        self.cursor.execute(query, fields)  # execute needs (sql [,parameters])

    def query(self, *sql):
        """Utility function to enter any query"""
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


# db = SqlDatabase('log.db')
# with db:
with SqlDatabase('log.db') as db:
    a = db.get('messages', '*')
    print(a)
    b = db.get_last('messages', '*')
    print(b)
    # db.write('messages', 'lvl', 'adfa', )
    # db.query("""insert into messages values(:dtg, :lvl, :msg);""",
    #     dict(dtg='1214241', lvl='dafda', msg='working?'))

with SqlDatabase('test.db') as db:
    db.create_table()
    # db.query("INSERT INTO logging VALUES(:target, :mac, :rssi, :epochtime, :dtg);",
    #          dict(target='target', mac='mac', rssi='rssi', epochtime='epoch', dtg='dtg'))
    db.write('target', 'mac', 'rssi', 'epoch', 'dtg')
