from datetime import datetime

from flask import Flask, request, render_template, session, url_for, redirect, flash
import os
app = Flask("environ")
app.secret_key = os.urandom(32)
app.logs = os.path.dirname(os.path.realpath(__file__)) + "/logs/"


def tail(filename, n=1):
    try:
        f = open(app.logs + filename, "rb")
        try:
            f.seek(-(256 * n), 2)
        except OSError:
            pass
        return "\n".join(list(map(lambda l: l.decode("utf8").rstrip(),
                                  f.readlines()[-n:]))[::-1])
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
    if 'username' in session:
        sensors.extend(private_sensors)

    return render_template("dashboard.html",
                           sensors={k: decode(tail(k), k) for k in sensors})


@app.route("/register")
def register():
    return "Registration form here"


@app.route("/login", methods=['GET', 'POST'])
def login():
    errors = {}
    if request.method == 'POST':
        if request.form.get('username') == 'admin':
            if request.form.get('password') == 'qwerty':
                session['uid'] = 1
                session['username'] = request.form.get('username')
                session['logged_in'] = datetime.now().isoformat(sep=' ')
                flash('Welcome home, sweet!')
                return redirect(url_for('dashboard'))
            else:
                errors['password'] = True
        else:
            errors['username'] = True
    return render_template("login.html", errors=errors)


@app.route("/logout")
def logout():
    if 'username' in session:
        session.clear()
        flash('Bye-bye!')

    return redirect(url_for('dashboard'))


@app.route("/log/<sensor>")
def log(sensor):
    if 'username' in session:
        return render_template("log.html", log=tail(sensor, 50), sensor=sensor)
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True)
