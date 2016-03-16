from flask import Flask, render_template
from os.path import join, dirname, realpath

from psutil import cpu_percent, virtual_memory

from utils import get_state, get_env
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

if __name__ == "__main__":
    app.run(port=27000, debug=True)
