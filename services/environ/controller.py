from flask import Flask, request, render_template
import logging
import os
app = Flask("environ")
app.logs = os.path.dirname(os.path.realpath(__file__)) + "/logs/"


def tail(filename, n=1):
    try:
        f = open(app.logs + filename, "rb")
        try:
            f.seek(-(256 * n), 2)
        except OSError:
            pass
        if n < 2:
            return f.readlines()[-1].decode("utf8")
        return list(map(lambda l: l.decode("utf8").rstrip(),
                        f.readlines()[-n:]))[::-1]
    except:
        return b""


def decode(raw, s_type):
    if s_type == "temperature":
        return raw
    elif s_type == "pressure":
        return raw
    elif s_type == "humidity":
        return raw
    elif "system_" in s_type:
        return raw
    else:
        return hash(raw) % 2 if raw else raw


@app.route("/")
def dashboard():
    # TODO: auth check
    auth = True
    sensors = ["temperature", "pressure", "humidity",
               "system_cpu", "system_mem"]
    private_sensors = [
        "window_kitchen", "window_livingroom", "window_bedroom",

        "door_main", "door_gate", "door_garage", "door_balcony",

        "light_kitchen", "light_livingroom", "light_bedroom", "light_bathroom",
        "light_toilet", "light_hall", "light_garden", "light_garage",

        "radiator_garage", "radiator_kitchen", "radiator_livingroom",
        "radiator_bedroom"
    ]
    if auth:
        sensors.extend(private_sensors)

    return render_template("dashboard.html",
                           sensors={k: decode(tail(k), k) for k in sensors},
                           # TODO: pass user
                           auth=auth)


@app.route("/register")
def register():
    return "Registration form here"


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return "Successful login"

    return "Login form here"


# TODO: auth only
@app.route("/log/<sensor>")
def log(sensor):
    return str({"log": tail(sensor, 50)})

if __name__ == "__main__":
    app.run()
