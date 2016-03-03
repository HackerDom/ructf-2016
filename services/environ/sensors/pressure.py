from random import choice
from time import sleep
from datetime import datetime


import string
avail = string.ascii_uppercase + string.digits

while True:
    current_time = datetime.now()
    if current_time.second != 0:
        sleep(1)
        continue

    # TODO: actual pressure info
    flag = "".join((choice(avail) for _ in range(31))) + "="
    pressure = sum(map(ord, flag)) % 100 + 50
    # END_TODO

    with open("logs/pressure", "a") as log:
        try:
            log.write("%s\t%s\n" % (current_time.isoformat(sep=" "), flag))
            with open("status/pressure", "w") as status:
                status.write(str(pressure))
        except IndexError:
            pass