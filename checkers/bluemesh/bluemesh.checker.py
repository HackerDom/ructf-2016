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

PORT = 16900
CPORT = 16901
CHECKER_NODES = ['10.23.' + str(i) + '.3' for i in range(1, 23)]

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

def send(request, socket):
	socket.sendall(request.encode('utf-8'))
	socket.sendall(b'\n')

def readline(socket_fd):
	return socket_fd.readline().rstrip('\n')

class State:
	def __init__(self, hostname):
		self.hostname = hostname

	def connect_to_checker(self):
		while True:
			try:
				s = socket.create_connection((random.choice(CHECKER_NODES), CPORT), 0.1)
				s.settimeout(10)
				return s
			except:
				time.sleep(0.1)

	def check(self):
		socket = self.connect_to_checker()
		socket_fd = socket.makefile('r')
		send("list", socket)
		line = readline(socket_fd)
		if not self.hostname in line:
			service_down(message="Node not found in cluster")
		else:
			service_ok()

	def put(self, flag_id, flag):
		socket = self.connect_to_checker()
		socket_fd = socket.makefile()
		send("put " + self.hostname + ":" + str(PORT) + " " + flag_id + " " + flag, socket)
		result = readline(socket_fd)
		
		time.sleep(2)
		
		if result == "done":
			service_ok(message=flag_id)
		else:
			service_mumble(message="Unexpected PUT response: " + result)

	def get(self, flag_id, flag):
		socket = self.connect_to_checker()
		socket_fd = socket.makefile()
		send("get " + self.hostname + ":" + str(PORT) + " " + flag_id, socket)
		result = readline(socket_fd)
		if result == flag:
			service_ok()
		else:
			service_corrupt(message="Unexpected GET response: " + result)

def handler_info(*args):
	service_ok(message="vulns: 1")

def handler_check(*args):
	hostname = args[0][0]
	
	state = State(hostname)
	state.check()

def handler_get(args):
	hostname, id, flag, vuln = args
	
	state = State(hostname)
	state.get(id, flag)

def handler_put(args):
	hostname, id, flag, vuln = args
	
	state = State(hostname)
	state.put(id, flag)

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
