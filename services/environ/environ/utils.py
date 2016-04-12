from os import scandir
from random import choice
from Crypto.Util.number import getPrime
from Crypto.Random import atfork
from psutil import cpu_percent, virtual_memory, disk_usage
from string import hexdigits


def downhill(p, g, A):
    atfork()
    p, g, A, b = int(p), int(g), int(A), getPrime(16)
    B = pow(g, b, p)
    if B < 2 or B > p - 1 or pow(B, (p - 1) // 2, p) != 1:
        return downhill(p, g, A)
    return B, pow(A, b, p)


def rosa():
    p, q = getPrime(256), getPrime(256)
    n, f = p * q, (p - 1) * (q - 1)
    e = choice((5, 17, 257, 65537, 4294967297))
    temp_d, x1, x2, y1, temp_e, temp_f = 0, 0, 1, 1, e, f
    while temp_e > 0:
        temp1, temp2 = temp_f // temp_e, temp_f % temp_e
        temp_f, temp_e = temp_e, temp2
        x = x2 - temp1 * x1
        y = temp_d - temp1 * y1
        x2, x1, temp_d, y1 = x1, x, y1, y

    if temp_f != 1:
        return rosa()

    d = temp_d + f
    if pow(pow(31337, e, n), d, n) != 31337:
        return rosa()
    return (e, n), (d, n)


def sign(data, key):
    return pow(data, key[0], key[1])


def check_sign(data, signature):
    return pow(int(signature), 65537, 633197242999008209490008491329443808268980823641679113835174611692369378754186972864703370204625897846201821676722099913149950262938990767863440878803796529847158724013323328604847947586971834988423281842052600123308233911599938650003590174828396869721395727120062112650487508848820762220187931324260300665624724912213282708291822907996914746946911228758354746497895760988497717700715365206296778950036225562293869733944715013264486229387524310482293488093849945347952576499648465117886629596300317154575706313779279292557418345813069851965797902762696666882346358222471837125797920613779707930683786866906177316646782647986953441178855477265342189114729084143383638336395788758259144688880816050705492938159037002541783161514057631214694490908412807683995312027990284140738176749012934701869996265112608260038780126226929192377735384133445395542707023436972889327345248198228419660999295134942171314568620598538982965136918129729023445690600317510534012765959575319828414752062364938190741470089153869764020001003884655373108679135037208418386218769818496545353654180897982636677420461266856754158090013843249798877172013202806744077584057010684329393919654887407525000881165092445645529418937003293463949187616174793040905914082671) == int(data)


def guid():
    return "".join([choice(hexdigits) for _ in range(6)])


def current_state(path):
    def ctime(obj):
        return obj.stat().st_ctime_ns
    try:
        return open(sorted(filter(lambda f: f.is_file(), scandir(path)), key=ctime, reverse=True)[0].path, 'rb').read()
    except:
        return None


PERIMETER = ["window_kitchen", "livingroom", "bedroom", "playroom", "main", "garage"]

LIGHTS = ["kitchen", "chandelier", "floor-lamp", "table", "bathroom", "bed", "garage"]

RADIATORS = ["climate", "block", "portable"]


def get_state(path):
    state = current_state(path)
    if not state or len(state) < 30:
        return {"system": {"cpu": cpu_percent(percpu=True), "mem": virtual_memory().percent, "disk": disk_usage('/').percent}, "temperature": 0, "pressure": 0, "humidity": 0, "perimeter": {}, "lights": {}, "radiators": {}}
    return {
        "system": {"cpu": cpu_percent(percpu=True), "mem": virtual_memory().percent, "disk": disk_usage('/').percent},
        "temperature": int(open('/sys/class/thermal/thermal_zone0/temp').read()) / 1000 - 30,
        "pressure": int.from_bytes(state, byteorder='big') % 1000 / 10 + 50,
        "humidity": int.from_bytes(state, byteorder='big') % 100,
        "perimeter": {s: 47 < state[o] < 58 for o, s in enumerate(PERIMETER)},
        "lights": {s: 47 < state[o + len(PERIMETER)] < 58 for o, s in enumerate(LIGHTS)},
        "radiators": {s: (state[15 + o] - 65) / 57 * 13 + 17 for o, s in enumerate(RADIATORS)},
    }
