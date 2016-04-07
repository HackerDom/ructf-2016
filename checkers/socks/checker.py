#!/usr/bin/env python3

import sys
import traceback
import socket

PORT = 9123

def ructf_error(status=110, message=None, error=None, exception=None):
    if message:
        sys.stdout.write(message)
        sys.stdout.write("\n")

    sys.stderr.write("{}\n".format(status))
    if error:
        sys.stderr.write(error)
        sys.stderr.write("\n")

    if exception:
        print(dir(exception))
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


def connect_to_service(hostname):
    try:
        return socket.create_connection((hostname, PORT))
    except Exception as e:
        service_down(message=str(e), exception=e)

def check_reply(request, socket, socket_fd):
    try:
        socket.sendall(request.encode("utf-8"))
        socket.sendall(b'\n')
        reply = socket_fd.readline().strip()
    except Exception as e:
        return service_down(message=str(e), exception=e)

    status, value = reply.split(" ", 1)
    if status not in ("[OK]", "[ERR]"):
        return service_mumble(message="Bad status", error=make_err_message("Bad status", request, reply))

    if status == "[ERR]":
        return service_corrupt(message="Service return error on request!", error=make_err_message("Error on request", request, reply))

    return status, value


def handler_info(*args):
    service_ok(message="vulns: 1")

def handler_check(*args):
    service_ok()

def handler_get(args):
    _, _, hostname, id, flag, vuln = args
    socket = connect_to_service(hostname)
    socket_fd = socket.makefile()

    request = "GET\t{}".format(id)
    status, value = check_reply(request, socket, socket_fd)

    if value != flag:
        return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", request, reply))

    return service_ok()

def handler_put(args):
    _, _, hostname, id, flag, vuln = args
    socket = connect_to_service(hostname)
    socket_fd = socket.makefile()

    request = "PUT\t{}\t{}".format(id, flag)
    status, value = check_reply(request, socket, socket_fd)

    return service_ok()

HANDLERS = {
    'info' : handler_info,
    'check' : handler_check,
    'get' : handler_get,
    'put' : handler_put,
}

def main():
    handler = HANDLERS[sys.argv[1]]
    handler(sys.argv)


if __name__ == "__main__":
    main()
