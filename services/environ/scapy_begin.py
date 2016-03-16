from scapy.all import *
import os
from sys import platform
from scapy.layers.dot11 import Dot11Beacon
entropy = "RuCTF_"


def ssid(pkt):
    global entropy
    if pkt.haslayer(Dot11Beacon):
        if "RuCTF_" in pkt.info:
            if pkt.info != entropy:
                entropy = pkt.info
                with open("status/entropy", "w") as status:
                    status.write(entropy.replace("RuCTF_", ""))

if platform != "darwin":
    sniff(iface='en1', prn=ssid)

else:
    from time import sleep
    from subprocess import Popen
    from threading import Thread
    SLEEP_TIME = 30


    class scan(Thread):
        def run(self):
            path = "/tmp/"
            dirList = os.listdir(path)
            for fileName in dirList:
                if "airportSniff" in fileName:
                    try:
                        sniff(offline=path + fileName, prn=ssid)
                    except:
                        pass
                    os.remove(path + fileName)

    while True:
        p = Popen("airport sniff 1 > /dev/null", shell=True)
        sleep(SLEEP_TIME)
        Popen("kill -HUP %s" % p.pid, shell=True)
        scan().start()
