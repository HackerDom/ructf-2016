import random
import time
import datetime
import string
from utils import tail, xor, decode

avail = string.ascii_uppercase + string.digits

while True:
    flag = "".join((random.choice(avail) for _ in range(31))) + "="
    with open("logs/window_kitchen", "a") as log:
        try:
            pressure = tail("logs/pressure").split("\t")[1]
            output = xor(flag, pressure).decode("utf8")
            log.write("%s\t%s\n"
                      % (datetime.datetime.now().isoformat(sep=" "), output))
            with open("status/window_kitchen", "w") as status:
                status.write(str(decode(flag, "window_kitchen")))
        except IndexError:
            pass

    time.sleep(10)
