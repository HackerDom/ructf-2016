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
	return ''.join(random.choice(string.ascii_lowercase) for _ in range(l + random.randint(-l//2, l//2)))

def check_status(response):
	if response.status_code != 200:
		service_mumble(error='status code is {}. Content: {}\n'.format(response.status_code, response.text))
		
def check_cookie(cookies):
	if cookies is None:
		service_mumble(error='no cookies =(')
	if (not 'auth' in cookies) or (cookies.get('auth') == ''):
		service_mumble(error="auth cookie not found. '{}'".format(cookies))

def check_response(response):
	check_status(response)
	check_cookie(response)

def get_dashboards(text):
	rdash = re.compile(r"<a href='/dashboard/view/\?dashboardId=(\d+)'>([^<]+)</a>", re.IGNORECASE)
	return set((id, name) for id, name in rdash.findall(text))

class State:
	def __init__(self, hostname):
		self.base_addr = 'http://{}:{}/'.format(hostname, PORT)
		self.session = requests.Session()
	def get(self, url):
		url = self.base_addr + url
		response = None
		try:
			response = self.session.get(url)
		except Exception as ex:
			service_mumble(error=url, exception=ex)
#		print(list(map(lambda r : r.url, response.history)), response.url)
		check_status(response)
		return response
	def post(self, url, d):
		url = self.base_addr + url
		response = None
		try:
			response = self.session.post(url, data=d)
		except Exception as ex:
			service_mumble(error='{}\n{}'.format(url, d), exception=ex)
#		print(list(map(lambda r : r.url, response.history)), response.url)
		check_status(response)
		check_cookie(self.session.cookies)
		return response
	def login(self, username, password):
		return self.post('user/login/', {'username': username, 'password': password})
	def register(self):
		username = get_rand_string(8)
		password = get_rand_string(16)
		self.post('user/register/', {'username': username, 'password': password})
		return username, password
	def create_dashboard(self, description=None):
		name = get_rand_string(10)
		if description is None:
			description = get_rand_string(50)
		response = self.post('dashboard/create/', {'name': name, 'description': description})
		r = re.compile('dashboardid=(\d+)$', re.IGNORECASE)
		m = r.search(response.url)
		if m is None:
			service_mumble(error="can't find dashboardId in '{}'".format(response.url))
		return (m.group(1), name)
	def get_dashboard(self, id, name=None):
		response = self.get('dashboard/view/?dashboardId=' + id)
		rname = re.compile('<h2>([^<]*)</h2>')
		m = rname.search(response.text)
		if m is None:
			service_mumble(error="can't found dashboard name")
		name = m.groups(1)
		rdescription = re.compile('<p>([^<]*)</p>')
		m = rdescription.search(response.text)
		if m is None:
			service_mumble(error="can't found dashboard description")
		description = m.group(1)
		return name, description
	def logout(self):
		response = self.get('user/logout/')
	def check_dashboards(self, dashboards):
		response = self.get('dashboard/all/')
		all_dashboards = get_dashboards(response.text)
		if all_dashboards >= set(dashboards):
			return
		service_mumble(error='not all dashboards is found: {} vs {}'.format(all_dashboards, set(dashboards)))
	def check_my_dashboards(self, dashboards):
		response = self.get('dashboard/my/')
		all_dashboards = get_dashboards(response.text)
		if all_dashboards == set(dashboards):
			return
		service_mumble(error='list of dashboards are not equals')


def handler_info(*args):
	service_ok(message="vulns: 1")

def handler_check(*args):
	hostname = args[0][0]
	state = State(hostname)
	username, password = state.register()
	state.logout()
	state.login(username, password)
	dashboards = []
	for i in range(random.randint(2, 10)):
		dashboards.append(state.create_dashboard())
		state.get_dashboard(dashboards[-1][0])
	state.check_dashboards(dashboards)
	state.check_my_dashboards(dashboards)
	state = State(hostname)
	state.check_dashboards(dashboards)
	state.login(username, password)
	state.check_dashboards(dashboards)
	state.check_my_dashboards(dashboards)
	service_ok()

def handler_get(args):
	hostname, id, flag, vuln = args
	username, password, dashboard, name = id.split()
	state = State(hostname);
	state.check_dashboards([(dashboard, name)])
	state.login(username, password)

	_, description = state.get_dashboard(dashboard)

	if description != flag:
		return service_corrupt(message="Bad flag", error=make_err_message("Bad flag", dashboard, description))

	return service_ok()

def handler_put(args):
	hostname, id, flag, vuln = args
	state = State(hostname)
	username, password = state.register()
	for i in range(random.randint(0, 5)):
		state.create_dashboard()
	dashboard, name = state.create_dashboard(flag)
	for i in range(random.randint(0, 5)):
		state.create_dashboard()

	return service_ok(message="{}\n{}\n{}\n{}".format(username, password, dashboard, name))

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
