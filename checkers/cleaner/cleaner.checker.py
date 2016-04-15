#!/usr/bin/env python3

import sys
import traceback
import string
import random
import re
import binascii
import socket
import collections
import time

PORT = 12500
DELIM = "========================================================="
HELLO_LINES = 15
BASE = 2
HEIGHT = 8

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
    return ''.join(random.choice(string.ascii_letters) for _ in range(l))

def deduplicate(program):
    cur = None
    cnt = 0
    result = ''
    for c in program:
        if not (c in 'LRUD'):
            if cur is not None:
                result += cur
                result += "{0:02d}".format(cnt)
            cur = None 
            cnt = 0
            result += c
        elif cur == c:
            cnt += 1
        else:
            if cur is not None:
                result += cur
                result += "{0:02d}".format(cnt)
            cur = c
            cnt = 1
    return result

def print_room(room):
    lines = []
    for i in range(HEIGHT):
        line = ""
        for x in room:
            line += str(x[i])
        lines.append(line)
    lines.reverse()
    print("\n".join(lines))

def move_near(x, y, i, j):
    if x + 1 == i and y == j:
        return "R"
    elif x - 1 == i and y == j:
        return "L"
    elif x == i and y + 1 == j:
        return "U"
    elif x == i and y - 1 == j:
        return "D"
    else:
        return None

def move(x, y, i, j, room, path):
    log = ''

    if x == i and y == j:
        return log, path

    while path:
        near = move_near(x, y, i, j)
        if near is not None:
            log += near
            path.append((x, y))
            break
        else:
            new_x, new_y = path[-1]
            path = path[:-1]
            if x == new_x and y == new_y:
                new_x, new_y = path[-1]
                path = path[:-1]

            log += move_near(x, y, new_x, new_y)
            x, y = new_x, new_y

    return log, path

def dfs(room, ii, jj):
    log = ''
    queue = collections.deque()
    x, y = None, None
    path = []

    queue.appendleft((ii,jj))

    while len(queue) != 0:
        (i, j) = queue.popleft()

        if room[i][j] == 2:
            continue

        if x is not None:
            move_log, path = move(x, y, i, j, room, path)
            log += move_log
        else:
            log += "N{0:02d}{1:02d}".format(i, j)
            path.append((i, j))

        x, y = i, j
        room[i][j] = 2

        if j < HEIGHT - 1 and not room[i][j + 1]:
            queue.appendleft((i, j + 1))
        if i < len(room) - 1 and not room[i + 1][j]:
            queue.appendleft((i + 1, j))
        if j > 0 and not room[i][j - 1]:
            queue.appendleft((i, j - 1))
        if i > 0 and not room[i - 1][j]:
            queue.appendleft((i - 1, j))
    return log, room

def traverse_room(room):
    log = ''
    for i in range(len(room)):
        for j in range(HEIGHT):
            if not room[i][j]:
                dfs_log, room = dfs(room, i, j)
                log += dfs_log
    return log, room

def generate_program(flag):
    hex_flag = binascii.hexlify(flag.encode('utf-8'))
    room = []
    for x in range(len(hex_flag) // BASE):
        col = [int(x) for x in list(bin(int(hex_flag[x*BASE:(x+1)*BASE], 16))[2:])]
        col.reverse()
        while (len(col) < 8):
            col.append(0)
        room.append(col)
    log, room2 = traverse_room(room)
    log = deduplicate(log)
    return log

def generate_room(flag):
    trash = string.ascii_lowercase.replace('w', '') + '          '
    room = ''
    for c in flag:
        b = ord(c)
        for x in range(8):
            if b & (1 << x):
                room += 'W'
            else:
                room += random.choice(trash)
    return room

def send(request, socket):
    try:
        socket.sendall(request.encode('utf-8'))
        socket.sendall(b'\n')
    except Exception as e:
        service_down(message=str(e), exception=e)
        raise e

def readline(socket_fd):
    try:
        return socket_fd.readline().rstrip('\n')
    except Exception as e:
        service_mumble(message=str(e), exception=e)
        raise e

def skip_hello(socket_fd):
    for _ in range(HELLO_LINES):
        readline(socket_fd)

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
        room_name = get_rand_string(15)
        program_name = get_rand_string(15)
        room = generate_room(flag)

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

        time.sleep(0.5)

        return room_name, program_name, password 

    def run(self, room, program, password):
        socket = self.connect_to_service()
        socket_fd = socket.makefile()
        skip_hello(socket_fd)
        send("run", socket)
        send(password, socket)
        send(room, socket)
        send(program, socket)
        return readline(socket_fd)

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
    room, program, password = id.split('\t')

    state = State(hostname);

    rooms = state.list_rooms()
    if not room in rooms:
        return service_corrupt(message="No such room", error=make_err_message("No such room:", room, "\n".join(rooms)))

    programs = state.list_programs()
    if not program in programs:
        return service_corrupt(message="No such program", error=make_err_message("No such program", program, "\n".join(programs)))

    enc_flag = generate_room(flag)
    enc_flag_w = re.sub('[^W]', ' ', enc_flag)

    room_conf = state.get_room(room, password)
    room_conf_w = re.sub('[^W]', ' ', room_conf)

    if room_conf_w != enc_flag_w:
        return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", enc_flag_w, room_conf_w))

    log = state.run(room, program, password)

    if 'E' in log:
        return service_corrupt(message="Bad run result: error", error="Bad run result : {} {}".format(log, flag))

    good_log = generate_program(flag)
    if good_log != log:
        return service_corrupt(message="Bad run result", error="Bad run result : {} {}".format(good_log, log))

    return service_ok()

def handler_put(args):
    hostname, id, flag, vuln = args
    state = State(hostname)
    room, program, password = state.put(flag)

    return service_ok(message="{}\t{}\t{}".format(room, program, password))

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
