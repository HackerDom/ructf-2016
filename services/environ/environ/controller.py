from uuid import uuid4

from flask import Flask, render_template
from os.path import join, dirname, realpath

from psutil import cpu_percent, virtual_memory
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import LLC

from utils import get_state, get_env, check_sign, downhill, rosa, sign
from scapy.all import *
from multiprocessing import Process


class Env(Packet):
    fields_desc = [
        IntField('decoded', 31337),
        IntField("team_id", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len),
        FieldLenField("len_sign", None, length_of="sign"),
        StrLenField("sign", "", length_from=lambda pkt: pkt.len_sign),
    ]

bind_layers(LLC, Env, ssap=0)


app = Flask("environ")
app.sensors_path = join(dirname(realpath(__file__)), 'sensors')


@app.route("/")
def dashboard():
    sensors = {
        "temperature": get_env('t'),
        "pressure": get_env('p'),
        "humidity": get_env('h'),
        "system_cpu": cpu_percent(),
        "system_mem": virtual_memory().percent
    }

    sensors.update(get_state(app.sensors_path))

    return render_template("index.html", sensors=sensors)


@app.route("/<path:sensor>")
def show_raw(sensor):
    try:
        return open(app.sensors_path + "/%s" % sensor).read()
    except:
        return "", 404


class Listener(Process):
    def __init__(self, team_id):
        super(Listener, self).__init__()
        self.id = team_id
        self.dh_keys = []
        app.public_key, self.private_key = rosa()

    def send(self, data, private=True):
        encoded_data = int.from_bytes(data.encode("utf8"), byteorder='big')
        encoded_data *= self.dh_keys[-1] if len(self.dh_keys) and private else 1

        pkg = RadioTap() / Dot11(type=2) / LLC() / Env(
            team_id=self.id,
            data=str(encoded_data),
            sign=str(sign(encoded_data, self.private_key))
        )
        sendp(pkg, count=5, inter=0.2, verbose=0)

    def handle(self, pkt):
        if not check_sign(pkt.data, pkt.sign):
            return
        try:
            data = int(pkt.data).to_bytes(
                300, byteorder='big').lstrip(b'\0')
            if b"start:" in data:
                try:
                    B, dh_key = downhill(*data.split(b":")[1:4])
                except:
                    return
                else:
                    self.dh_keys.append(dh_key)
                    if len(self.dh_keys) > 10:
                        self.dh_keys.pop(0)
                    self.send(b'pub:%d' % B, private=False)
                    return
            else:
                raise Exception('encoded')
        except:
            if not len(self.dh_keys):
                return
            for dh_key in self.dh_keys[::-1]:
                try:
                    data = (int(pkt.data) / dh_key).to_bytes(
                        300, byteorder='big').lstrip(b'\0')
                    if b"put:" in data:
                        sens_data = data.split(b'put:')[1]
                        sensor = str(uuid4())
                        with open(app.sensors_path + "/" + sensor, 'wb') as s:
                            s.write(sens_data)
                        self.send(b'ACCEPT:%s' % sensor.encode("utf8"))
                        return
                except:
                    pass

    def run(self):
        print("Sniff started")
        sniff(lfilter=lambda p: p.haslayer(Env) and
                                p.decoded == 31337 and p.team_id == self.id,
              prn=self.handle)


if __name__ == "__main__":
    listener = Listener(1)
    listener.start()
    app.run(port=27000)

