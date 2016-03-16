from base64 import b64encode
from os import urandom
from random import choice, randint
from sys import argv, stderr
from socket import error as net_error, socket

__author__ = 'm_messiah'

OK, GET_ERROR, CORRUPT, FAIL, INTERNAL_ERROR = 101, 102, 103, 104, 110
PORT = 27000
SENSORS = ("main", "door_main", "window_kitchen")


def gen_dh():
    n = 5

    # Remove this rule?
    while (n - 2) % 3 == 0:
        n = randint(100, 200)

    p = pow(pow(2, n) - 1, 2) - 2
    g = choice([2, 3, 5, 7, 11, 13, 17, 23])
    a = int.from_bytes(urandom(40), byteorder='big')
    A = pow(g, a, p)
    if A < 2 or A > p - 1 or pow(A, (p - 1) // 2, p) != 1:
        return gen_dh()
    return p, g, A, a


def shared_secret(p, a, B):
    if B < 2 or B > p - 1 or pow(B, (p - 1) // 2, p) != 1:
        return None
    return pow(B, a, p)


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
    answer = ""

    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, None, "Incorrect parameters")
    try:

        p, g, A, a = gen_dh()
        data = int.from_bytes("start:%s:%s:%s" % (p, g, A), byteorder='big')
        client_id = addr
        # TODO: sign data
        # TODO: get pub_key for client
        # TODO: send wi-fi signed_data to client
        # TODO: listen wi-fi to answer and check client_sign
        # TODO: if packet.captured: B = packet.data
        B = int()
        secret = shared_secret(p, a, B)
        data = int.from_bytes("put:%s" % flag, byteorder='big') * secret

        # 36 bytes

        # TODO: sign data
        # TODO: send wi-fi signed_data to client
        # TODO: listen wi-fi to answer and check client_sign
        # TODO: if packet.captured:
        # packed.data = int(packed.data).to_bytes(50, byteorder='big').lstrip(b'\0')
        packet_data = b""
        if b"ACCEPT:" in packet_data:
            flag_id = packet_data.split(b"ACCEPT:")[1]
            if flag_id:
                close(OK, flag_id, None)
            else:
                close(CORRUPT, "ID not found",
                      "ID not found in %s" % packet_data)
        else:
            close(CORRUPT, "Data not accepted by environ",
                  "Not accepted: %s" % packet_data)
        # TODO: else (packet not captured or timeout)
        # close(CORRUPT, "No answer",
        #       "Service did not respond to put")

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