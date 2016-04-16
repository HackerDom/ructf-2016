#!/usr/bin/env python3

import sys
import traceback
import requests
import string
import random
import re
import json

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
	rdash = re.compile(r"<a [^>]*href='/dashboard/view/\?dashboardId=(\d+)'>([^<]+)</a>", re.IGNORECASE)
	return set((id, name) for id, name in rdash.findall(text))

def check_sensors(text, config):
	draw = re.compile(r"<script>draw\('#sensor(\d+)', (\[[^\]]+\])\);</script>")
	sensors = draw.findall(text)
	if len(sensors) < 4:
		service_mumble(error="can't find sensors\n{}".format(text))
	vv = []
	for i in range(len(sensors)):
		if str(i) != sensors[i][0]:
			service_mumble(error='sensor in wrong position')
		try:
			values = json.loads(sensors[i][1])
		except Exception as ex:
			service_mumble(error="can't parse values", exception=ex)
		if not isinstance(values, list):
			service_mumble(error="values must be a list".format(values))
		if len(values) != 300:
			service_mumble(error="values' length must be 300")
		for v in values:
			if not isinstance(v, float):
				service_mumble(error="each value must be a float {}".format(type(v)))
		vv.append(values)
#TODO check non zeroes
	if config is None:
		return
	config = config + ' ' * (-len(config) % 4)
	config = config.encode()
	inital = vv[:4]
	vv = vv[4:]
	for i in range(0, len(config), 4):
		for j in range(300):
			if abs(config[i] * inital[0][j] + config[i + 1] * inital[1][j] + config[i + 2] * inital[2][j] + config[i + 3] * inital[3][j] - vv[i // 4][j]) > 1e-6:
				service_mumble(error="error is too large")


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
			service_down(error=url, exception=ex)
		check_status(response)
		return response
	def post(self, url, d):
		url = self.base_addr + url
		response = None
		try:
			response = self.session.post(url, data=d)
		except Exception as ex:
			service_down(error='{}\n{}'.format(url, d), exception=ex)
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
	def create_dashboard(self, description=None, config=None, pub=None):
		name = get_rand_string(10)
		if description is None:
			description = get_rand_string(50)
		if config is None:
			config = get_rand_string(50)
		if pub is None:
			pub = random.choice(['', 'on'])
		response = self.post('dashboard/create/', {'name': name, 'description': description, 'public': pub, 'sensors': config})
		r = re.compile('dashboardid=(\d+)$', re.IGNORECASE)
		m = r.search(response.url)
		if m is None:
			service_mumble(error="can't find dashboardId in '{}'".format(response.url))
		return m.group(1), name
	def get_dashboard(self, id, name=None, config=None):
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
		check_sensors(response.text, config)
		description = m.group(1)
		return name, description
	def logout(self):
		response = self.get('user/logout/')
	def check_dashboards(self, dashboards):
		response = self.get('dashboard/all/')
		all_dashboards = get_dashboards(response.text)
		if all_dashboards >= set(dashboards):
			return
		service_mumble(error='not all dashboards is found')
	def check_my_dashboards(self, dashboards):
		response = self.get('dashboard/my/')
		all_dashboards = get_dashboards(response.text)
		if all_dashboards == set(dashboards):
			return
		service_mumble(error='list of dashboards are not equals')
	def check_public_dashboards(self, dashboard):
		response = self.get('dashboard/all/')
		link = r"<a class='public' href='/dashboard/view/\?dashboardId={}'>".format(dashboard)
		r = re.compile(link, re.IGNORECASE)
		if not r.search(response.text):
			service_mumble(error="can't find public dashboard link")


def handler_info(*args):
	service_ok(message="vulns: 1:1")

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

def handler_get_1(state, id, flag):
	username, password, dashboard, name = id.split()
	state.check_dashboards([(dashboard, name)])
	state.login(username, password)
	_, description = state.get_dashboard(dashboard)
	if description != flag:
		service_corrupt(message="Bad flag", error=make_err_message("Bad flag", dashboard, description))
	service_ok()

def handler_get_2(state, id, flag):
	state.check_public_dashboards(id)
	state.get_dashboard(id, None, flag)
	service_ok()

def handler_get(args):
	hostname, id, flag, vuln = args
	state = State(hostname);
	if vuln == '1':
		handler_get_1(state, id, flag)
	else:
		handler_get_2(state, id, flag)

def handler_put_1(state, flag):
	username, password = state.register()
	for i in range(random.randint(0, 5)):
		state.create_dashboard()
	dashboard, name = state.create_dashboard(flag, None, '')
	for i in range(random.randint(0, 5)):
		state.create_dashboard()
	service_ok(message="{}\n{}\n{}\n{}".format(username, password, dashboard, name))

def handler_put_2(state, flag):
	username, password = state.register()
	for i in range(random.randint(0, 5)):
		state.create_dashboard()
	dashboard, name = state.create_dashboard(None, flag, 'on')
	for i in range(random.randint(0, 5)):
		state.create_dashboard()
	service_ok(message=str(dashboard))

def handler_put(args):
	hostname, id, flag, vuln = args
	state = State(hostname)
	if vuln == '1':
		handler_put_1(state, flag)
	else:
		handler_put_2(state, flag)

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
