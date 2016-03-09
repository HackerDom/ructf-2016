import threading
import socketserver
from datetime import datetime
from utils import decode


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(256).strip()
        flag = self.server.handler(data)
        if not flag:
            self.request.sendall(b"0\n")
            return
        with open("logs/%s" % self.server.sensor, "a") as l:
            try:
                l.write("%s\t%s\n" % (datetime.now().isoformat(sep=" "), flag))
                with open("status/%s" % self.server.sensor, "w") as status:
                    status.write(str(decode(flag, self.server.sensor)))
            except IndexError:
                pass
        self.request.sendall(b"1\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class Sensor(threading.Thread):
    def __init__(self, port, sensor_name, handler):
        self.server = ThreadedTCPServer(('0.0.0.0', 27000 + port), Handler)
        self.server.handler = handler
        self.server.sensor = sensor_name
        super(Sensor, self).__init__(target=self.server.serve_forever)
