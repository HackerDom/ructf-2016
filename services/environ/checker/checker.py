from base64 import b64encode
from sys import argv, stderr
from socket import error as net_error, socket

__author__ = 'm_messiah'

OK, GET_ERROR, CORRUPT, FAIL, INTERNAL_ERROR = 101, 102, 103, 104, 110
PORT = 27000
SENSORS = (None, "door_main", "window_kitchen")


def xor(s1, s2):
    if not isinstance(s1, bytes):
        s1 = s1.encode("utf8")
    if not isinstance(s2, bytes):
        s2 = s2.encode("utf8")
    return b64encode(bytes(x ^ y for x, y in zip(s1, s2)))


def close(code, public="", private=""):
    if public:
        print(public)
    if private:
        print(private, file=stderr)
    exit(code)


def check(*args):
    addr = args[0]
    if not addr:
        close(INTERNAL_ERROR, None, "Check without ADDR")

    for i in range(1, 3):
        try:
            sock = socket()
            sock.connect((addr, PORT + i))
            sock.send(b"check\n")
            recv = sock.recv(3).strip()
            try:
                recv = int(recv)
            except ValueError:
                close(CORRUPT, "problem with %s" % SENSORS[i])
        except net_error:
            close(FAIL, "No connection to %s" % SENSORS[i])


def put(*args):
    addr = args[0]
    flag_id = args[1]
    flag = args[2]
    vuln = int(args[3]) if len(args) > 3 else 1
    answer = ""

    salt = b"RuCTF_"  # get or set from/to wifi

    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, None, "Incorrect parameters")
    try:
        if vuln == 1:
            sensor = SENSORS[vuln]
            data = xor(flag, salt + sensor.upper().encode("utf8"))
            sock = socket()
            sock.connect((addr, PORT + vuln))
            sock.send(data + b"\n")
            recv = sock.recv(3).strip()
            try:
                recv = int(recv)
                if recv > 0:
                    close(OK, sensor, None)
                else:
                    close(CORRUPT, "can't put in %s sensor" % sensor,
                          "%s sensor put answer: %s" % (sensor, recv))
            except ValueError:
                close(CORRUPT, "can't put in %s sensor" % sensor,
                      "%s sensor put answer: %s" % (sensor, recv))

    except net_error:
        close(FAIL, "No connection to %s" % addr)
    except (KeyError, IndexError):
        close(CORRUPT, "JSON structure", "Bad answer in %s" % answer)


def get(*args):
    addr = args[0]
    checker_flag_id = args[1]
    flag = args[2]
    vuln = int(args[3]) if len(args) > 3 else 1
    answer = ""
    if not addr or not checker_flag_id or not flag:
        close(INTERNAL_ERROR, None, "Incorrect parameters")
    try:
        pass
    except net_error:
        close(FAIL, "No connection to %s" % addr)
    except (KeyError, IndexError):
        close(CORRUPT, "JSON structure", "Bad answer in %s" % answer)
    except ValueError:
        close(GET_ERROR, private="Incorrect vuln")


def info(*args):
    close(OK, "vulns: 3:1")


COMMANDS = {'check': check, 'put': put, 'get': get, 'info': info}


def not_found(*args):
    print("Unsupported command %s" % argv[1], file=stderr)
    return INTERNAL_ERROR


if __name__ == '__main__':
    try:
        COMMANDS.get(argv[1], not_found)(*argv[2:])
    except Exception as e:
        close(INTERNAL_ERROR, "Bad-ass checker", "INTERNAL ERROR: %s" % e)