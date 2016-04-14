#!/usr/bin/env python3

import requests
import sqlite3
import sys
import traceback
import os
import os.path
import random

PORT = 3030
DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILENAME = os.path.join(DIR, 'db.sqlite3')
THING_FILENMAME = os.path.join(DIR, 'things.txt')

def ructf_error(status=110, message=None, error=None, exception=None, request=None, reply=None):
    if message:
        sys.stdout.write(message)
        sys.stdout.write("\n")

    sys.stderr.write("{}\n".format(status))
    if error:
        sys.stderr.write(error)
        sys.stderr.write("\n")

    if request or reply:
        sys.stderr.write(make_err_message(message, request, reply))
        sys.stderr.write("\n")

    if exception:
        sys.stderr.write("Exception: {}\n".format(exception))
        traceback.print_tb(exception.__traceback__, file=sys.stderr)

    sys.exit(status)

def service_ok(status=101, message="Service OK", *args, **kwargs):
    return ructf_error(status, message, *args, **kwargs)

def service_corrupt(status=102, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def service_mumble(status=103, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def service_down(status=104, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def make_err_message(message, request, reply):
    return "{}\n->\n{}\n<-\n{}\n=".format(message, request, reply)

def handler_info(*args):
    service_ok(message="vulns: 1")

def handler_check(*args):
    service_ok()

def handler_get(args, db, things):
    _, _, hostname, id, flag, vuln = args
    thing = db.get_doc(id)
    request = "http://{0}:{3}/search?text={1}&owner={2}".format(hostname, thing, id, PORT)
    reply = None
    print(request)
    try:
        r = requests.get(request)
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Cant connect to server", exception=e, request=request, reply=reply)

    for r in reply.split("\n"):
        if flag in r:
            return service_ok()

    return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", request, reply))


def handler_put(args, db, things):
    _, _, hostname, id, flag, vuln = args
    request = "http://{0}:{3}/set?text={1}&owner={2}".format(hostname, flag, id, PORT)
    reply = None
    try:
        thing = things.random()
        db.save_doc(id, thing)
        r = requests.post(request, data=thing)
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Cant connect to server", exception=e, request=request, reply=reply)


    return service_ok()


HANDLERS = {
    'info' : handler_info,
    'check' : handler_check,
    'get' : handler_get,
    'put' : handler_put,
}

class DB:
    DB_VERSION = 1

    def __init__(self, filename):
        self.filename = filename
        new_databse = False

        if not os.path.exists(filename):
            new_databse = True

        conn = sqlite3.connect(filename)
        self.conn = conn
        c = conn.cursor()
        if new_databse:
            c.execute('''CREATE TABLE config (key VARCHAR(128) PRIMARY KEY, value VARCHAR(128))''')
            c.execute('''INSERT INTO config VALUES ("version", ?)''', (self.DB_VERSION,))

            c.execute('''CREATE TABLE documents (id VARCHAR(128) PRIMARY KEY, document TEXT)''')
        else:
            version = None
            for row in c.execute('''SELECT value FROM config WHERE key = ?''', ("version",)):
                version = int(row[0])

            if version != self.DB_VERSION:
                print("Version missmatch: {} != {}".format(version, self.DB_VERSION), file=sys.stderr)
                os.remove(filename)
                return self.__init__(filename)
        conn.commit()

    def get_doc(self, id):
        for row in self.conn.execute('''SELECT document FROM documents WHERE id = ?''', (id,)):
            return row[0]

    def save_doc(self, id, document):
        c = self.conn.cursor()
        c.execute('''INSERT INTO documents VALUES (?, ?)''', (id, document))
        self.conn.commit()


class Things:
    def __init__(self, filename):
        self.filename = filename
        with open(filename) as fn:
            self.things = list(map(lambda x: x.strip(), fn.readlines()))

    def random(self):
        return random.choice(self.things)


def main():
    db = DB(DB_FILENAME)
    things = Things(THING_FILENMAME)

    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv, db, things)


if __name__ == "__main__":
    main()
