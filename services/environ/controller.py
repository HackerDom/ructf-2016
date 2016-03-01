from datetime import datetime, timedelta
from hashlib import sha256
from flask import (Flask, request, render_template,
                   session, url_for, redirect, flash)
from random import sample, randint
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
    # DEV: TEST VALUES
    if "radiator_" in s_type:
        return randint(1,100)
    if "light_" in s_type or "window" in s_type or "door" in s_type:
        return randint(0,1) == 0
    if s_type == "temperature":
        return randint(0, 400) / 10.0
    if s_type == "pressure":
        return randint(500, 1500) / 10.0
    if s_type == "humidity":
        return randint(0, 100)
    if s_type == "system_cpu":
        return randint(0, 1000) / 10.0
    if s_type == "system_mem":
        return randint(0, 1000)
    # END DEV

    if not raw:
        return None
    try:
        timestamp, data = raw.split("\t")
    except ValueError:
        data = raw.strip()
    if s_type == "temperature":
        return float(data)
    elif s_type == "pressure":
        return float(data)
    elif s_type == "humidity":
        return float(data)
    elif "system_" in s_type:
        return float(data)
    elif "radiator_" in s_type:
        return int(data)
    else:
        return False if hash(data) % 2 else True

app = Flask("environ")
app.secret_key = os.urandom(32)
app.logs = os.path.dirname(os.path.realpath(__file__)) + "/logs/"
app.users = Users(os.path.dirname(os.path.realpath(__file__)) + "/users.db")
app.private_sensors = [
    "window_kitchen", "window_livingroom", "window_bedroom", "window_playroom",

    "door_main", "door_gate", "door_garage", "door_garden",

    "light_kitchen", "light_livingroom", "light_bedroom", "light_bathroom",
    "light_toilet", "light_hall", "light_garden", "light_garage",

    "radiator_garage", "radiator_kitchen", "radiator_livingroom",
    "radiator_bedroom"
]


@app.route("/")
def dashboard():
    sensors = ["temperature", "pressure", "humidity",
               "system_cpu", "system_mem"]
    session['username'] = 'admin'
    if 'username' in session:
        sensors.extend(app.private_sensors)

    return render_template("dashboard.html",
                           sensors={k: decode(tail(k), k) for k in sensors})


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


def accept_task(tasks):
    current = datetime.now()
    iso = '%Y-%m-%d %H:%M:%S.%f'
    for sensor, times in tasks.items():
        last_log = tail(sensor, n=20)
        if not last_log:
            return False
        last_values = []
        for l in last_log.split('\n'):
            time, value = l.split('\t')
            if current - datetime.strptime(time, iso) > timedelta(minutes=1):
                break
            last_values.append(decode(value, sensor))

        counter = 0
        last = last_values[0]
        for i in last_values[1:]:
            if i != last:
                counter += 1
                last = i
        if counter < times:
            return False
    return True


@app.route("/register", methods=['GET', 'POST'])
def register():
    error_username, error_belong = None, None
    if request.method == 'POST':
        try:
            data = request.form
            if 'task' not in session:
                raise ValueError
            if not accept_task(session['task']):
                raise ValueError
            app.users[data.get('username', "")] = data.get('password', "")
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except (KeyError, AttributeError):
            error_username = True
        except ValueError:
            error_belong = True

    task, task_text = generate_task()
    session['task'] = task
    return render_template("register.html",
                           error_username=error_username,
                           error_belong=error_belong,
                           tasks=task_text)


@app.route("/login", methods=['GET', 'POST'])
def login():
    error_username, error_password = None, None
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
            error_password = True
        except LookupError:
            error_username = True
    return render_template("login.html",
                           error_username=error_username,
                           error_password=error_password)


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
