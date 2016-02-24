import random
import time
import datetime
import string

avail = string.ascii_uppercase + string.digits

while True:
    flag = "".join((random.choice(avail) for _ in range(31))) + "="
    with open("logs/window_kitchen", "a") as log:
        log.write("%s\t%s\n"
                  % (datetime.datetime.now().isoformat(sep=" "), flag))
    time.sleep(10)
