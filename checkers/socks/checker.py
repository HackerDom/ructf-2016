#!/usr/bin/env python3

import base64
import os
import os.path
import random
import requests
import sqlite3
import sys
import traceback

PORT = 3030
DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILENAME = os.path.join(DIR, 'db.sqlite3')
THING_FILENMAME = os.path.join(DIR, 'things.txt')

def ructf_error(status=110, message=None, error=None, exception=None, request=None, reply=None, body=None):
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

    if body:
        sys.stderr.write("BODY:\n")
        sys.stderr.write(body)
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

def handler_get(args, things):
    _, _, hostname, id_big, flag, vuln = args
    id, thing = base64.b64decode(id_big).decode("utf-8").split("===", 1)
    request = "http://{0}:{3}/search?text={1}&owner={2}".format(hostname, thing, id, PORT)
    reply = None
    try:
        r = requests.get(request)
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Server error: {}".format(e), exception=e, request=request, reply=reply)

    for r in reply.split("\n"):
        if flag in r:
            return service_ok(message="OK", request=request, reply=reply)

    return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", request, reply))


def handler_put(args, things):
    _, _, hostname, id, flag, vuln = args
    thing = things.random()
    id_big = "{}==={}".format(id, thing)
    request = "http://{0}:{3}/set?text={1}&owner={2}".format(hostname, flag, id, PORT)
    reply = None
    thing = None
    try:
        r = requests.post(request, data=thing)
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply, body=thing)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Server error: {}".format(e), exception=e, request=request, reply=reply, body=thing)


    return service_ok(message=base64.b64encode(id_big.encode("utf-8")).decode("utf-8"), request=request, reply=reply, body=thing)


HANDLERS = {
    'info' : handler_info,
    'check' : handler_check,
    'get' : handler_get,
    'put' : handler_put,
}

class Things:
    def __init__(self, filename):
        self.filename = filename
        with open(filename) as fn:
            self.things = list(map(lambda x: x.strip(), fn.readlines()))

    def random(self):
        return random.choice(self.things)


def main():
    things = Things(THING_FILENMAME)

    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv, things)


if __name__ == "__main__":
    main()
