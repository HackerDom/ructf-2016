import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from uuid import uuid4
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import LLC
import socket
from os import environ
from os.path import join, realpath, dirname
from multiprocessing import Pool, Manager, log_to_stderr

logger = log_to_stderr()
logger.setLevel(logging.WARNING)

from utils import check_sign, downhill, sign


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


def send(iface, team_id, cmd, data, stream, dh_key=1):
    encoded_data = int.from_bytes(data, byteorder='big')
    encoded_data *= dh_key
    pkg = RadioTap() / Dot11(type=2) / LLC() / Env(
        team_id=team_id,
        stream=stream,
        cmd=cmd,
        decoded=31337,
        data=str(encoded_data),
        sign=str(sign(encoded_data, private_key))
    )
    sendp(pkg, iface=iface, count=15, inter=0.2, verbose=0)


def handle(iface, team_id, pkt):
    try:
        if not check_sign(pkt['data'], pkt['sign']):
            return
    except:
        return

    if pkt['cmd'] == 0:
        try:
            data = int(pkt['data']).to_bytes(
                300, byteorder='big').lstrip(b'\0')
            if b"start:" in data and pkt['stream'] not in current_streams:
                try:
                    B, dh_key = downhill(*data.split(b':')[1:4])
                    current_streams.append(pkt['stream'])
                except:
                    return
                else:
                    if pkt['stream'] not in dh_keys:
                        dh_keys[pkt['stream']] = dh_key
                    send(iface, team_id, 1, b'pub:%d' % B, pkt['stream'])
                    return
        except:
            return

    elif pkt['cmd'] == 2 and pkt['stream'] in dh_keys:
        dh_key = dh_keys.get(pkt['stream'], 1)
        try:
            data = (int(int(pkt['data']) // dh_key)).to_bytes(
                300, byteorder='big').lstrip(b'\0')
            if b"put:" in data:
                sens_data = data.split(b'put:')[1]
                sensor = str(uuid4())
                with open(sensors.value + sensor, 'wb') as s:
                    s.write(sens_data)
                send(iface, team_id, 3, b'ACCEPT:%s' % sensor.encode("utf8"),
                     pkt['stream'], dh_key)
                logger.warning("new data by: %s" % sensor)
                del current_streams[current_streams.index(pkt['stream'])]
                del dh_keys[pkt['stream']]
                return
        except Exception as e:
            print(e)
            pass


def handle_async(pkt):
    pickle_pkt = dict(stream=pkt.stream, data=pkt.data,
                      cmd=pkt.cmd, sign=pkt.sign)
    pool.apply_async(handle, [IFACE, TEAM_ID, pickle_pkt])


if __name__ == '__main__':
    IFACE = environ.get('WIFICARD', 'wlan0')
    print(IFACE)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # TODO: change it to checksystem addr
        s.connect(("ructf.org", 80))
        TEAM_ID = int(s.getsockname()[0].split('.')[2])

    manager = Manager()
    dh_keys = manager.dict()
    current_streams = manager.list()
    sensors = manager.Value('c', join(dirname(realpath(__file__)), 'sensors/'))

    try:
        private_key = manager.list([
            int(i) for i in open(join(dirname(realpath(__file__)),
                                      'id.key')).read().split(':')])
    except:
        logger.error("Rosa private_key not found")
        exit(1)

    pool = Pool(processes=10)
    sniff(
        iface=IFACE,
        lfilter=lambda p:
        p.haslayer(Env) and p.decoded == 31337 and
        p.team_id == TEAM_ID and (p.cmd == 0 or p.cmd == 2),
        prn=handle_async
    )