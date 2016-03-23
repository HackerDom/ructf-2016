from os import urandom, scandir
from random import choice
from Crypto.Util import number


def downhill(p, g, A):
    if A < 2 or A > p - 1 or pow(A, (p - 1) // 2, p) != 1:
        return None, None

    b = int.from_bytes(urandom(40), byteorder='big')
    B = pow(g, b, p)
    if B < 2 or B > p - 1 or pow(B, (p - 1) // 2, p) != 1:
        return downhill(p, g, A)
    return B, pow(A, b, p)


def ex_eurika(a, b):
    d, x1, x2, y1, temp_b = 0, 0, 1, 1, b

    while a > 0:
        temp1, temp2 = temp_b // a, temp_b % a
        temp_b, a = a, temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2, x1, d, y1 = x1, x, y1, y

    if temp_b == 1:
        return d + b


def rosa():
    p, q = number.getPrime(256), number.getPrime(256)
    n, f = p * q, (p - 1) * (q - 1)
    e = choice((5, 17, 257, 65537, 4294967297))

    temp_d, x1, x2, y1, temp_e, temp_f = 0, 0, 1, 1, e, f

    while temp_e > 0:
        temp1, temp2 = temp_f // temp_e, temp_f % temp_e
        temp_f, temp_e = temp_e, temp2
        x = x2 - temp1 * x1
        y = temp_d - temp1 * y1
        x2, x1, temp_d, y1 = x1, x, y1, y

    if temp_f != 1:
        return rosa()

    d = temp_d + f

    if pow(pow(31337, e, n), d, n) != 31337:
        return rosa()
    return (e, n), (d, n)


def sign(data, key):
    return pow(data, key[0], key[1])


def check_sign(data, signature):
    return pow(
        int(signature),
        4294967297,
        3798516331466766966859797353966230419017725222735680227325678541054930545137024120151496321141097061641653294848058448185893124212469966621530373870392659
    ) == data


def current_state(path):
    def ctime(obj):
        return obj.stat().st_ctime_ns
    try:
        return open(
            sorted(filter(lambda f: f.is_file(), scandir(path)),
                   key=ctime, reverse=True)[0].path, 'rb').read()
    except:
        return None


def get_env(metric):
    from random import randint
    if metric == 't':
        return randint(0, 400) / 10
    elif metric == 'p':
        return randint(500, 1500) / 10
    elif metric == 'h':
        return randint(0, 100)
    return None

SWITCHES = [
    "window_kitchen", "window_livingroom", "window_bedroom", "window_playroom",

    "door_main", "door_garage",

    "light_kitchen", "light_lustre", "light_torchere", "light_table",
    "light_bathroom", "light_bed", "light_garage",
]
RADIATORS = [
    "radiator_climate", "radiator_block", "radiator_portable"
]


def get_state(path):
    result = {}
    state = current_state(path)
    if not state:
        return result
    if len(state) < 30:
        return result

    for offset, switch in enumerate(SWITCHES):
        result[switch] = 47 < state[offset] < 58
    for offset, sensor in enumerate(RADIATORS):
        result[sensor] = (state[15 + offset] - 65) / 57 * 13 + 17

    return result
