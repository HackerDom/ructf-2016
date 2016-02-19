from datetime import datetime
from hashlib import sha256
from flask import (Flask, request, render_template,
                   session, url_for, redirect, flash)
import os


class Users(object):
    def __init__(self, filename):
        self.filename = filename
        try:
            self._users = {
                l.split(':')[1]: dict(zip(['uid', 'username', 'password'],
                                          l.strip().split(':')))
                for l in open(self.filename, 'r').readlines()
            }
        except FileNotFoundError:
            self._users = {}
            open(self.filename, 'w').write("")

    def auth(self, username, password):
        if username not in self._users:
            raise LookupError
        user = self._users[username]
        if user['password'] != sha256(password.encode("utf8")).hexdigest():
            raise KeyError
        return user['uid'], user['username']

    def __setitem__(self, key, value):
        if key in self._users or ':' in key:
            raise KeyError
        user = {'uid': hash(key), 'username': key,
                'password': sha256(value.encode("utf8")).hexdigest()}
        with open(self.filename, 'a') as db:
            self._users[key] = user
            db.write("%(uid)s:%(username)s:%(password)s\n" % user)


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
        return ""


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

app = Flask("environ")
app.secret_key = os.urandom(32)
app.logs = os.path.dirname(os.path.realpath(__file__)) + "/logs/"
app.users = Users(os.path.dirname(os.path.realpath(__file__)) + "/users.db")


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


@app.route("/register", methods=['GET', 'POST'])
def register():
    errors = {}
    if request.method == 'POST':
        try:
            data = request.form
            app.users[data.get('username', "")] = data.get('password', "")
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except (KeyError, AttributeError):
            errors['username'] = True
    return render_template("register.html", errors=errors)


@app.route("/login", methods=['GET', 'POST'])
def login():
    errors = {}
    if request.method == 'POST':
        try:
            session['uid'], session['username'] = app.users.auth(
                request.form.get('username', ""),
                request.form.get('password', "")
            )
            session['logged_in'] = datetime.now().isoformat(sep=' ')
            flash('Welcome home, sweet!')
            return redirect(url_for('dashboard'))
        except KeyError:
            errors['password'] = True
        except LookupError:
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
