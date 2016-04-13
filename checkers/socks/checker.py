#!/usr/bin/env python3

import requests
import sqlite3
import sys
import traceback
import os
import os.path

PORT = 9123
DIR = os.path.dirname(os.path.abspath(__file__))

def ructf_error(status=110, message=None, error=None, exception=None):
    if message:
        sys.stdout.write(message)
        sys.stdout.write("\n")

    sys.stderr.write("{}\n".format(status))
    if error:
        sys.stderr.write(error)
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

def handler_get(args):
    _, _, hostname, id, flag, vuln = args
    request = "http://{0}:3000/search?text={1}&owner={1}".format(hostname, id)
    try:
        r = requests.get(request)
        r.raise_for_status()
        reply = r.text
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Protocol error", exception=e)

    for r in reply.split("\n"):
        if flag in r:
            return service_ok()

    return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", request, reply))


def handler_put(args):
    _, _, hostname, id, flag, vuln = args
    try:
        r = requests.post("http://{0}:3000/set?text={1}&owner={1}".format(hostname, id), data=flag)
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Protocol error", exception=e)


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

        if os.path.exists(filename):
            new_databse = True

        conn = sqlite3.connect(filename)
        if new_databse:
            c.execute('''CREATE TABLE config (key VARCHAR(128), value VARCHAR(128))''')
            c.execute('''INSERT INTO config VALUES ("version", ?))''', (self.DB_VERSION,))

            c.execute('''CREATE TABLE documents (id VARCHAR(128), document VARCHAR(128))''')
            conn.commit()
        else:
            c.execute('''SELECT value FROM config WHERE key = ?''', ("version",))
            version = c.fetchone()[0]
            if version != self.DB_VERSION:
                print >>sys.stderr, "Version missmatch: {} != {}".format(version, self.DB_VERSION)
                os.remove(filename)
                return self.__init__(filename)


def main():
    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv)


if __name__ == "__main__":
    main()
