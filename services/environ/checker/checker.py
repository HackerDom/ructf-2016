from base64 import b64encode
from os import urandom
from random import choice, randint
from sys import argv, stderr
from socket import error as net_error

import requests
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import LLC

__author__ = 'm_messiah'

OK, GET_ERROR, CORRUPT, FAIL, INTERNAL_ERROR = 101, 102, 103, 104, 110
PORT = 27000


class Env(Packet):
    fields_desc = [
        IntField('decoded', 31337),
        IntField("team_id", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len),
        LongField("sign", 0),
    ]

bind_layers(LLC, Env, ssap=0)


def send_package(team_id, data, secret=0):
    encoded_data = int.from_bytes(data.encode("utf8"), byteorder='big')
    if secret:
        encoded_data *= secret
    sign = 2707
    pkg = RadioTap() / Dot11(type=2) / LLC() / Env(
        team_id=team_id,
        data=str(encoded_data),
        sign=sign
    )
    sendp(pkg, count=5, inter=0.2, verbose=0)


def check_sign(pub_key, sign, data):
    if sign == 2707:
        return True
    else:
        return False


def receive_packet(team_id, pub_key, cmd):
    def is_env(pkt):
        if pkt.haslayer(Env):
            if pkt.decoded == 31337 and pkt.team_id == team_id:
                if check_sign(pub_key, pkt.sign, pkt.data):
                    return True
        return False

    captured = {p.data for p in sniff(lfilter=is_env, timeout=3)}
    for data in captured:
        try:
            data_bytes = int(data).to_bytes(300, byteorder='big').lstrip(b'\0')
            if cmd in data_bytes:
                return data_bytes.split(cmd)[1]
        except:
            pass
    return None


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


def put(*args):
    addr = args[0]
    flag_id = args[1]
    flag = args[2]

    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, None, "Incorrect parameters")
    #try:
    p, g, A, a = gen_dh()
    data = "start:%s:%s:%s" % (p, g, A)
    team_id = int(addr.split(".")[2])
    send_package(team_id, data)
    # TODO: get pub_key for client
    pub_key = 1

    B = receive_packet(team_id, pub_key, b'pub:')
    if not B:
        close(CORRUPT, "DH negotiation failed",
              "DH: not receive pub key (B)")

    secret = 0
    try:
        secret = shared_secret(p, a, int(B))
    except:
        close(CORRUPT, "DH negotiation wrong",
              "DH: received wrong pub key (B)")

    data = "put:%s" % flag
    send_package(team_id, data, secret)
    answer = receive_packet(team_id, pub_key, b'ACCEPT:')

    if answer:
        close(OK, flag_id, None)
    else:
        close(CORRUPT, "ID not found",
              "ID not found in ACCEPT")

    #except:
    #    close(FAIL, "No interface")


def get(*args):
    addr = args[0]
    flag_id = args[1]
    flag = args[2]
    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, None, "Incorrect parameters")
    try:
        answer = requests.get("http://%s:%s/%s" % (addr, PORT, flag_id))
        if answer.status_code != 200:
            close(GET_ERROR, private="Flag not found")
        if answer.text != flag:
            close(GET_ERROR, private="Bad flag by flag_id")
        close(OK)
    except:
        close(FAIL, "No connection to %s" % addr)


def info(*args):
    close(OK, "vulns: 1")


COMMANDS = {'check': check, 'put': put, 'get': get, 'info': info}


def not_found(*args):
    print("Unsupported command %s" % argv[1], file=stderr)
    return INTERNAL_ERROR


if __name__ == '__main__':
    try:
        COMMANDS.get(argv[1], not_found)(*argv[2:])
    except Exception as e:
        close(INTERNAL_ERROR, "Bad-ass checker", "INTERNAL ERROR: %s" % e)