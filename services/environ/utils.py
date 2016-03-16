from os import urandom, scandir


def downhill(p, g, A):
    if A < 2 or A > p - 1 or pow(A, (p - 1) // 2, p) != 1:
        return None, None

    b = int.from_bytes(urandom(40), byteorder='big')
    B = pow(g, b, p)
    if B < 2 or B > p - 1 or pow(B, (p - 1) // 2, p) != 1:
        return downhill(p, g, A)
    return B, pow(A, b, p)


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

    "door_main", "door_gate", "door_garage", "door_garden",

    "light_kitchen", "light_livingroom", "light_bedroom", "light_bathroom",
    "light_hall", "light_garden", "light_garage",
]
RADIATORS = [
    "radiator_garage", "radiator_kitchen", "radiator_livingroom",
    "radiator_bedroom"
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
