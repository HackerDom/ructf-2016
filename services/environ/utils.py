from base64 import b64encode
from datetime import datetime, timedelta
from random import randint


def xor(s1, s2):
    return b64encode(bytes(ord(x) ^ ord(y) for x, y in zip(s1, s2)))


def tail(filename, n=1):
    try:
        f = open(filename, "rb")
        try:
            f.seek(-(256 * n), 2)
        except OSError:
            pass
        return "\n".join(list(map(lambda l: l.decode("utf8").rstrip(),
                                  f.readlines()[-n:]))[::-1])
    except:
        return ""


def cat(filename):
    # DEV: TEST VALUES
    if "radiator_" in filename:
        return randint(1, 100)
    if "light_" in filename or "window" in filename or "door" in filename:
        return randint(0, 1) == 0
    if "temperature" in filename:
        return randint(0, 400) / 10.0
    if "pressure" in filename:
        return randint(500, 1500) / 10.0
    if "humidity" in filename:
        return randint(0, 100)
    if "system_cpu" in filename:
        return randint(0, 1000) / 10.0
    if "system_mem" in filename:
        return randint(0, 1000)
    # END DEV

    try:
        with open(filename) as f:
            status = f.read()
            try:
                return int(status)
            except ValueError:
                return float(status)
    except:
        return None


def decode(flag, s_type):
    if "window" in s_type:
        return hash(flag) % 2
    elif "pressure" in s_type:
        return sum(map(ord, flag)) % 100 + 50
    else:
        return hash(flag) % 2


def generate_task():
    # DEV: simple registration
    # sensors = {s: randint(1, 3)
    #            for s in sample(app.private_sensors, randint(2, 5))}
    # END DEV
    sensors = {'window_kitchen': 2}

    def humanise_task(task, times):
        phrase = ""
        if "light" in task or "radiator" in task:
            phrase += "Switch on and off "
        elif "window" in task or "door" in task:
            phrase += "Open and close "
        phrase += " ".join(task.split("_")[::-1])
        phrase += " %s times" % times
        return phrase

    text = [humanise_task(t, i) for t, i in sensors.items()]
    return sensors, text


def cmp_min(d1, d2):
    return (d1.replace(second=0, microsecond=0) ==
            d2.replace(second=0, microsecond=0))


def accept_task(logs, tasks):
    current = datetime.now()
    iso = '%Y-%m-%d %H:%M:%S.%f'
    pressures = [
        (datetime.strptime(l.split("\t")[0], iso), l.split("\t")[1])
        for l in tail(logs + "pressure", n=3).split("\n")
    ]

    for sensor, times in tasks.items():
        last_log = tail(logs + sensor, n=20)
        if not last_log:
            return False
        last_values = []
        for l in last_log.split('\n'):
            time, value = l.split('\t')
            time = datetime.strptime(time, iso)
            if current - time > timedelta(seconds=100):
                break
            try:
                pressure = [p[1] for p in pressures if cmp_min(p[0], time)][0]
            except IndexError:
                pressure = bytes(32).decode("utf8")
            last_values.append(decode(xor(pressure, value), sensor))

        counter = 0
        last = last_values[0]
        for i in last_values[1:]:
            if i != last:
                counter += 1
                last = i
        if counter < times:
            return False
    return True
