from datetime import datetime

from flask import (Flask, request, render_template,
                   session, url_for, redirect, flash)
from random import sample, randint
import os

from utils import tail, generate_task, accept_task, cat
from models import Users
app = Flask("environ")
app.secret_key = os.urandom(32)
app.path = os.path.dirname(os.path.realpath(__file__))
app.users = Users(app.path + "/users.db")
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
                           sensors={k: cat(app.path + "/status/" + k)
                                    for k in sensors})


@app.route("/register", methods=['GET', 'POST'])
def register():
    error_username, error_belong = None, None
    if request.method == 'POST':
        try:
            data = request.form
            if 'task' not in session:
                raise ValueError
            if not accept_task(app.path + "/logs/", session['task']):
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
        return render_template("log.html",
                               log=tail(app.path + "/logs/" + sensor, 50),
                               sensor=sensor)
    return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.run(debug=True)
