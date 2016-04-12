#!/usr/bin/env python3

import sys
import traceback
import string
import random
import re
import binascii
import socket

PORT = 12500
DELIM = "====================="
HELLO_LINES = 5

def ructf_error(status=110, message=None, error=None, exception=None):
    if message:
        sys.stdout.write(message)
        sys.stdout.write("\n")

    sys.stderr.write("{}\n".format(status))
    if error:
        sys.stderr.write(error)
        sys.stderr.write("\n")

    if exception:
        sys.stderr.write("Exception: {}\n".format(exception))
        traceback.print_tb(exception.__traceback__, file=sys.stderr)

    sys.exit(status)

def service_ok(status=101, message="Service OK", *args, **kwargs):
    return ructf_error(status, message, *args, **kwargs)

def service_corrupt(status=102, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def service_mumble(status=103, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def service_down(status=104, *args, **kwargs):
    return ructf_error(status, *args, **kwargs)

def make_err_message(message, request, reply):
    return "{}\n->\n{}\n<-\n{}\n=".format(message, request, reply)

def get_rand_string(l):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))

def send(request, socket):
    try:
        socket.sendall(request.encode('utf-8'))
        socket.sendall(b'\n')
    except Exception as e:
        service_down(message=str(e), exception=e)
        raise e

def readline(socket_fd):
    try:
        return socket_fd.readline().rstrip()
    except Exception as e:
        service_mumble(message=str(e), exception=e)
        raise e

def skip_hello(socket_fd):
    for _ in range(HELLO_LINES):
        readline(socket_fd)

def generate_program(flag):
    return "N0000"

class State:
    def __init__(self, hostname):
        self.hostname = hostname

    def connect_to_service(self):
        try:
            return socket.create_connection((self.hostname, PORT))
        except Exception as e:
            service_down(message=str(e), exception=e)
            raise e

    def do_list(self, entity):
        socket = self.connect_to_service()
        socket_fd = socket.makefile('r')
        skip_hello(socket_fd)
        send("list", socket)
        send(entity, socket)
        line = readline(socket_fd)
        if line != DELIM:
            return service_mumble(message="Bad response", error=make_err_message("Bad status", "list\n{}".format(entity), line))
        line = readline(socket_fd)
        result = []
        while line != DELIM:
            result.append(line)
            line = readline(socket_fd)
        return result

    def list_rooms(self):
        return self.do_list("rooms")

    def list_programs(self):
        return self.do_list("programs")

    def get_room(self, room, password):
        socket = self.connect_to_service()
        socket_fd = socket.makefile()
        skip_hello(socket_fd)
        send("get_room", socket)
        send(password, socket)
        send(room, socket)
        line = readline(socket_fd)
        return line

    def put(self, flag):
        password = get_rand_string(32)
        room_name = get_rand_string(32)
        program_name = get_rand_string(32)
        room = binascii.hexlify(flag.encode('utf-8')).decode('utf-8')

        socket = self.connect_to_service()
        socket_fd = socket.makefile()
        skip_hello(socket_fd)
        send("upload", socket)
        send(password, socket)
        send("room", socket)
        send(room_name, socket)
        send(room, socket)
        send("program", socket)
        send(program_name, socket)
        send(generate_program(flag), socket)

        return room_name, program_name, password 

def handler_info(*args):
    service_ok(message="vulns: 1")

def handler_check(*args):
    hostname = args[0][0]
    state = State(hostname)
    rooms = state.list_rooms()
    programs = state.list_programs()
    service_ok()

def handler_get(args):
    hostname, id, flag, vuln = args
    room, program, password = id.split()

    state = State(hostname);

    rooms = state.list_rooms()
    if not room in rooms:
        return service_corrupt(message="No such room", error=make_err_message("No such room:", room, "\n".join(rooms)))

    programs = state.list_programs()
    if not program in programs:
        return service_corrupt(message="No such program", error=make_err_message("No such program", program, "\n".join(programs)))

    room = state.get_room(room, password)
    if room != binascii.hexlify(flag):
        return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", flag, room))

#    log = service.run(room, program, password)

#    if 'E' in log:
#        return service_corrupt(message="Bad run result", error="Bad run result : {} {}".format(room, flag))

    return service_ok()

def handler_put(args):
    hostname, id, flag, vuln = args
    state = State(hostname)
    room, program, password = state.put(flag)

    return service_ok(message="{}\n{}\n{}".format(room, program, password))

HANDLERS = {
    'info' : handler_info,
    'check' : handler_check,
    'get' : handler_get,
    'put' : handler_put,
}

def main():
    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv[2:])

if __name__ == "__main__":
    main()
