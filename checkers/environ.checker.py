import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from os import environ
from random import choice, randint
from sys import argv, stderr
import requests
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import LLC
from Crypto.Util import number
from multiprocessing import Pool
from multiprocessing.context import TimeoutError

__author__ = 'm_messiah'

OK, GET_ERROR, CORRUPT, FAIL, INTERNAL_ERROR = 101, 102, 103, 104, 110
PORT = 27000
IFACE = environ.get('WIFICARD', 'wlo1')


class Env(Packet):
    fields_desc = [
        IntField('decoded', 31337),
        IntField('stream', 0),
        IntField('cmd', 0),
        IntField("team_id", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len),
        FieldLenField("len_sign", None, length_of="sign"),
        StrLenField("sign", "", length_from=lambda pkt: pkt.len_sign),
    ]

bind_layers(LLC, Env, ssap=0)


def send_package(team_id, cmd, data, stream, secret=1):
    encoded_data = int.from_bytes(data.encode("utf8"), byteorder='big')
    if secret:
        encoded_data *= secret
    sign = pow(
        encoded_data,
        416630781277800814953814580513424110047377680960014751160419299104297608231045831268928067045544928314141858100670009192591240905724326104212998727066806749775991859512985467386335248727366212496311835445519206288314961971649794077627215397698248772695210744234116886975514935938154766139111402330969569637045781583906208354776080495577200020108407556136499586164796389907166922237671055715487887786799244986759178031755557941345975177131220887691189096137799980824487098948957705003486690593888372619125282018749562562425210093659325238513650871460900036152105522975867533767774813200290043263911168611238356626767175435037031592618362267430363591558037274501963991875264047536819786553572102321569423719412238250605238240363922701792636849938648331077868628126881709247599501399540465597820044852593299499505038180936557649245135529256877460871112784752981624686300459846296292486993748346207809123629291846064014335221587323672733973420287032968282124022323956687252471100340715794873395808679397290092512810609160427004215773972691065223939827557113966792915102828090948248858696881189121556761133072592276642984898368959004066150858410041541634754689994600656660584789661194932334670195455527607156767471664815501851249574634337,
        633197242999008209490008491329443808268980823641679113835174611692369378754186972864703370204625897846201821676722099913149950262938990767863440878803796529847158724013323328604847947586971834988423281842052600123308233911599938650003590174828396869721395727120062112650487508848820762220187931324260300665624724912213282708291822907996914746946911228758354746497895760988497717700715365206296778950036225562293869733944715013264486229387524310482293488093849945347952576499648465117886629596300317154575706313779279292557418345813069851965797902762696666882346358222471837125797920613779707930683786866906177316646782647986953441178855477265342189114729084143383638336395788758259144688880816050705492938159037002541783161514057631214694490908412807683995312027990284140738176749012934701869996265112608260038780126226929192377735384133445395542707023436972889327345248198228419660999295134942171314568620598538982965136918129729023445690600317510534012765959575319828414752062364938190741470089153869764020001003884655373108679135037208418386218769818496545353654180897982636677420461266856754158090013843249798877172013202806744077584057010684329393919654887407525000881165092445645529418937003293463949187616174793040905914082671
    )

    pkg = RadioTap() / Dot11(type=2) / LLC() / Env(
        team_id=team_id,
        cmd=cmd,
        stream=stream,
        data=str(encoded_data),
        sign=str(sign)
    )
    for i in range(10):
        time.sleep(randint(10, 100) / 1000)
        sendp(pkg, iface=IFACE, verbose=0)


def check_sign(pub_key, sign, data):
    try:
        return pow(int(sign), int(pub_key[0]), int(pub_key[1])) == int(data)
    except:
        return False


def receive_packet(team_id, pub_key, cmd_type, cmd, stream, secret=1):
    def is_env(pkt):
        if pkt.haslayer(Env):
            if (pkt.decoded == 31337 and pkt.team_id == team_id and
                    pkt.stream == stream and pkt.cmd == cmd_type):
                if check_sign(pub_key, pkt.sign, pkt.data):
                    return True
        return False

    def success(p):
        try:
            if not is_env(p):
                return False
            data_bytes = int(
                int(p.data) // secret
            ).to_bytes(300, byteorder='big').strip(b'\0')
            return True if cmd in data_bytes else None
        except:
            return None

    captured = sniff(iface=IFACE, lfilter=is_env, stop_filter=success)
    for capt in captured[::-1]:
        try:
            data_bytes = int(int(capt.data) // secret).to_bytes(300, byteorder='big').strip(b'\0')
            if cmd in data_bytes:
                return data_bytes.split(cmd)[1]
        except:
            pass
    return None


def gen_dh():
    p, a = number.getPrime(64), number.getPrime(32)
    g = choice([2, 3, 5, 7, 11, 13, 17, 23])
    A = pow(g, a, p)
    if A < 2 or A > p - 1 or pow(A, (p - 1) // 2, p) != 1:
        return gen_dh()
    return p, g, A, a


def shared_secret(p, a, B):
    if B < 2 or B > p - 1 or pow(B, (p - 1) // 2, p) != 1:
        return None
    return pow(B, a, p)


def close(code, public="", private=""):
    if public:
        print(public)
    if private:
        print(private, file=stderr)
    exit(code)


def check(*args):
    addr = args[0]
    if not addr:
        close(INTERNAL_ERROR, private="Check without ADDR")
    addr = args[0]
    try:
        answer = requests.get("http://%s:%s/" % (addr, PORT), timeout=3)
        if answer.status_code != 200:
            close(GET_ERROR, private="Bad status_code in /")
        if "Perimeter" not in answer.text or "Lights" not in answer.text:
            close(GET_ERROR, private="Broken index.html")
        answer = requests.get("http://%s:%s/id_pub" % (addr, PORT), timeout=2)
        if answer.status_code != 200:
            close(GET_ERROR, private="Bad status_code in /id_pub")
        if ":" not in answer.text:
            close(GET_ERROR, private="Broken id_pub")
        close(OK)
    except requests.exceptions.RequestException:
        close(FAIL, "No connection to %s" % addr)


def put(*args):
    addr = args[0]
    flag_id = args[1]
    flag = args[2]
    stream = randint(0, 10000)
    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, private="Incorrect parameters")
    pool = Pool(processes=1)
    pub_key = []
    try:
        pub_key = [
            int(i)
            for i in requests.get("http://%s:27000/id_pub" % addr, timeout=2).text.split(":")
        ]
    except requests.exceptions.RequestException:
        close(FAIL, "Pubkey is not available")
    p, g, A, a = gen_dh()
    data = "start:%s:%s:%s" % (p, g, A)
    team_id = int(addr.split(".")[2])
    B = pool.apply_async(receive_packet, (team_id, pub_key, 1, b'pub:', stream))
    send_package(team_id, 0, data, stream)
    try:
        B = B.get(timeout=5)
    except TimeoutError:
            close(CORRUPT, "DH negotiation failed",
                  "DH: not receive pub key (B)")

    secret = 1
    try:
        secret = shared_secret(p, a, int(B))
    except:
        close(CORRUPT, "DH negotiation wrong",
              "DH: received wrong pub key (B)")

    data = "put:%s" % flag
    answer = pool.apply_async(receive_packet, (team_id, pub_key, 3, b'ACCEPT:', stream, secret))
    send_package(team_id, 2, data, stream, secret)
    try:
        answer = answer.get(timeout=5)
        close(OK, answer.decode("utf8"))
    except TimeoutError:
        close(CORRUPT, "ID not found",
              "ID not found in ACCEPT")


def get(*args):
    addr = args[0]
    flag_id = args[1]
    flag = args[2]
    if not addr or not flag_id or not flag:
        close(INTERNAL_ERROR, private="Incorrect parameters")
    try:
        answer = requests.get("http://%s:%s/%s" % (addr, PORT, flag_id), timeout=5)
        if answer.status_code != 200:
            close(GET_ERROR, private="Flag not found")
        if answer.text != flag:
            close(GET_ERROR, private="Bad flag by flag_id")
        close(OK)
    except requests.exceptions.RequestException:
        close(FAIL, "No connection to %s" % addr)


def info(*args):
    close(OK, "vulns: 1")


COMMANDS = {'check': check, 'put': put, 'get': get, 'info': info}


def not_found(*args):
    close(INTERNAL_ERROR, private="Unsupported command %s" % argv[1])


if __name__ == '__main__':
    try:
        COMMANDS.get(argv[1], not_found)(*argv[2:])
    except Exception as e:
        close(INTERNAL_ERROR, "Bad-ass checker", "INTERNAL ERROR: %s" % e)
