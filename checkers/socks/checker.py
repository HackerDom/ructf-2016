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


UA = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.11875 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12017 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12018 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12084 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12084 Safari/537.36',

    'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/33.0.1750.152 Chrome/33.0.1750.152 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/34.0.1847.116 Chrome/34.0.1847.116 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/36.0.1985.125 Chrome/36.0.1985.125 Safari/537.36',
    'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/38.0.2125.111 Chrome/38.0.2125.111 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/38.0.2125.111 Chrome/38.0.2125.111 Safari/537.36',

    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
    'Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0',
    'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0',

    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
]


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

    sys.stderr.flush()
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

def handler_check(args, *other):
    _, _, hostname = args
    request = "http://{0}:{1}/".format(hostname, PORT)
    reply = None
    try:
        r = requests.get(request)
        r.raise_for_status()
        reply = r.text
        return service_ok()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Server error: {}".format(e), exception=e, request=request, reply=reply)
    except OSError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)


def make_request(things):
    things_list = things.split()
    if len(things_list) < 3:
        return things

    things_out = []
    for _ in range(3):
        t = random.choice(things_list)
        things_list.remove(t)
        things_out.append(t)
    return " ".join(things_out)


def handler_get(args, things):
    _, _, hostname, id_big, flag, vuln = args
    id, thing_full = base64.b64decode(id_big).decode("utf-8").split("===", 1)
    things = make_request(thing_full)

    request = "http://{0}:{3}/search?text={1}&owner={2}".format(hostname, things, id, PORT)
    reply = None
    try:
        r = requests.get(request, headers={ "User-Agent" : random.choice(UA) })
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Server error: {}".format(e), exception=e, request=request, reply=reply)
    except OSError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)


    for r in reply.split("\n"):
        if flag in r:
            return service_ok(request=request, reply=reply)

    return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", request, reply))


def handler_put(args, things):
    _, _, hostname, id, flag, vuln = args
    thing = things.random()
    id_big = "{}==={}".format(id, thing)
    request = "http://{0}:{3}/set?text={1}&owner={2}".format(hostname, flag, id, PORT)
    reply = None
    try:
        r = requests.post(request, data=thing, headers={ "User-Agent" : random.choice(UA) })
        reply = r.text
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply, body=thing)
    except requests.exceptions.HTTPError as e:
        return service_mumble(message="Server error: {}".format(e), exception=e, request=request, reply=reply, body=thing)
    except OSError as e:
        return service_down(message="Cant connect to server", exception=e, request=request, reply=reply)


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
            self.things = list(filter(None, map(lambda x: x.strip(), fn.readlines())))

    def random(self):
        return random.choice(self.things)


def main():
    things = Things(THING_FILENMAME)

    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv, things)


if __name__ == "__main__":
    main()
