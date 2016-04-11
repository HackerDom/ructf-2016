#!/usr/bin/env python3

import sys
import traceback
import requests
import string
import random
import re

PORT = 6725

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

def get_rand_string(l):
	return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))

def check_status(response):
	if response.status_code != 200:
		service_mumble(error='status code is {}. Content: {}\n'.format(response.status_code, response.text))
		
def check_cookie(cookies):
	if cookies is None:
		service_mumble(error='no cookies =(')
	for c in cookies:
		if c.name == 'auth' and c.value != '':
			return
	service_mumble(error="auth cookie not found. '{}'".format('|'.join(map(str, response.cookies))))

def check_response(response):
	check_status(response)
	check_cookie(response)

class State:
	def __init__(self, hostname):
		self.base_addr = 'http://{}:{}/'.format(hostname, PORT)
		self.session = requests.Session()
	def login(self, username, password):
		response = self.session.post(self.base_addr + 'user/login', data={'username': username, 'password': password})
		check_status(response)
		check_cookie(self.session.cookies)
	def register(self):
		username = get_rand_string(8)
		password = get_rand_string(16)
		response = self.session.post(self.base_addr + 'user/register', data={'username': username, 'password': password})
		check_status(response)
		check_cookie(self.session.cookies)
		return username, password
	def create_dashboard(self, description=None):
		name = get_rand_string(10)
		if description is None:
			description = get_rand_string(50)
		response = self.session.post(self.base_addr + 'dashboard/create', data={'name': name, 'description': description})
		check_status(response)
		r = re.compile('dashboardid=(\d+)$', re.IGNORECASE)
		m = r.search(response.url)
		if m is None:
			service_mumble(error="can't find dashboardId in '{}'".format(response.url))
		return m.group(1)
	def get_dashboard(self, id):
		response = self.session.get(self.base_addr + 'dashboard/view?dashboardId=' + id)
		check_status(response)
		rname = re.compile('<h2>([^<]*)</h2>')
		m = rname.search(response.text)
		if m is None:
			service_mumble(error="can't found dasboard name")
		name = m.groups(1)
		rdescription = re.compile('<p>([^<]*)</p>')
		m = rdescription.search(response.text)
		if m is None:
			service_mumble(error="can't found dasboard description")
		description = m.group(1)
		return name, description
	def logout(self):
		response = self.session.get(self.base_addr + 'user/logout')
		check_status(response)

def handler_info(*args):
	service_ok(message="vulns: 1")

def handler_check(*args):
	hostname = args[0][0]
	state = State(hostname)
	username, password = state.register()
	state.logout()
	for i in range(10):
		state.login(username, password)
		dashboard = state.create_dashboard()
		state.get_dashboard(dashboard)
		state.logout()
	service_ok()

def handler_get(args):
	hostname, id, flag, vuln = args
	username, password, dashboard = id.split()
	state = State(hostname);
	state.login(username, password)

	_, description = state.get_dashboard(dashboard)

	if description != flag:
		return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", dashboard, description))

	return service_ok()

def handler_put(args):
	hostname, id, flag, vuln = args
	state = State(hostname)
	username, password = state.register()
	dashboard = state.create_dashboard(flag)

	return service_ok(message="{}\n{}\n{}".format(username, password, dashboard))

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
