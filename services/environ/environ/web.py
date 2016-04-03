from os.path import join, dirname, realpath
from flask import Flask, render_template
from utils import get_state, rosa

app = Flask("environ")
app.sensors_path = join(dirname(realpath(__file__)), 'sensors')
app.rosa_key = rosa()

with open(join(dirname(realpath(__file__)), 'id.key'), 'w') as w:
    w.write("{0}:{1}".format(*app.rosa_key[1]))


@app.route("/")
def dashboard():
    sensors = get_state(app.sensors_path)
    return render_template("index.html", sensors=sensors)


@app.route("/id_pub")
def show_pub():
    return "{0}:{1}".format(*app.rosa_key[0])


@app.route("/<path:sensor>")
def show_raw(sensor):
    try:
        return open(app.sensors_path + "/{0:s}".format(sensor)).read()
    except:
        return "", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=27000, debug=True)
