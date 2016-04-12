from os.path import join, dirname, realpath
from flask import Flask, render_template, send_file, abort
from utils import get_state, rosa

app = Flask("environ")
app.sensors_path = join(dirname(realpath(__file__)), 'sensors')
app.rosa_key = rosa()

with open(join(dirname(realpath(__file__)), 'id.key'), 'w') as w:
    w.write("{0}:{1}".format(*app.rosa_key[1]))


@app.route("/")
def dashboard(): return render_template("index.html", sensors=get_state(app.sensors_path))


@app.route("/id_pub")
def show_pub(): return "{0}:{1}".format(*app.rosa_key[0])


@app.route("/<path:sensor>")
def show_raw(sensor):
    try:
        return send_file(join(app.sensors_path, sensor))
    except FileNotFoundError:
        abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=27000)
