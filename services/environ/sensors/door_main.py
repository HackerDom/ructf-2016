from base64 import b64decode
from base_sensor import Sensor
from utils import xor, tail


def handler(data):
    try:
        if len(data) > 1:
            salt = tail("status/entropy").strip().encode("utf8")
            return xor(b64decode(data), salt + b"DOOR_MAIN")
        else:
            return None
    except:
        return None

sensor = Sensor(1, "door_main", handler)
sensor.start()
