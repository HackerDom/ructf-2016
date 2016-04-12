#!/user/bin/python3
# do stuff
import uuid
import random
import string
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from httpchecker import *
from randomizer import *

GET = 'GET'
POST = 'POST'
PORT = 3000


class StrongboxChecker(HttpCheckerBase, Randomizer):
    def session(self, addr):
        s = r.Session()
        s.headers[
            'User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0'
        s.headers['Accept'] = '*/*'
        s.headers['Accept-Language'] = 'en-US,en;q=0.5'
        return s

    def url(self, addr, suffix):
        return 'http://{}:{}/{}'.format(addr, PORT, suffix)

    def parseresponse(self, response):
        if response.status_code != 200:
            print(response.text)
            raise HttpWebException(response.status_code, response.url)
        try:
            result = {"url": response.url,
                      "page": BeautifulSoup(response.text, "html5lib")}

            return result
        except ValueError:
            raise response.exceptions.HTTPError('failed to parse response')

    def spost(self, s, addr, suffix_get, suffix_post, data=None):
        soup = BeautifulSoup(s.get(self.url(addr, suffix_get)).content,
                             "html5lib")
        csrf_data = soup.find("input", {"name": "authenticity_token"}).get(
            "value")
        data.update({'authenticity_token': csrf_data})
        response = s.post(self.url(addr, suffix_post), data, timeout=5)
        return self.parseresponse(response)

    def sget(self, s, addr, suffix):
        response = s.get(self.url(addr, suffix), timeout=5)
        return self.parseresponse(response)

    def randword(self):
        word = ''
        rnd = random.randrange(2, 10)
        for i in range(rnd):
            word += random.choice(string.ascii_lowercase)
        return word

    def checkSignup(self, result):
        try:
            exit_element = result["page"].find("a", {'data-method': 'delete'})
            if exit_element and exit_element.text.strip() == 'Sign out':
                return False
            return True
        except (AttributeError, TypeError):
            return True

    #TODO
    def checkAddThing(self, result, flag):
        try:
            list_things = result["page"].find_all("li")
            for thing in list_things:
                if thing.text.strip() == flag:
                    return False
            return True
        except (AttributeError, TypeError):
            return True

    def put(self, addr, flag_id, flag, vuln):
        session = self.session(addr)
        user = self.randuser()
        result = self.spost(session, addr, 'signup', 'users', user)
        if not result or self.checkSignup(result):
            print('registration failed')
            return EXITCODE_MUMBLE

        thing = {
            'thing[title]': self.randTitle(),
            'thing[content]': flag
        }
        result = self.spost(session, addr, '/', '/things',thing)
        if self.checkAddThing(result, thing['thing[title]']):
            print('put msg failed')
            return EXITCODE_MUMBLE

        print(
            '{}:{}:{}'.format(
                user['user[email]'],
                user['user[password]'],
                thing['thing[title]']
            )
        )
        return EXITCODE_OK

    def get(self, addr, flag_id, flag, vuln):
        s = self.session(addr)
        parts = flag_id.split(':', 3)
        user = {'session[email]': parts[0], 'session[password]': parts[1]}

        result = self.spost(s, addr, '/signin', 'sessions', user)
        if self.checkSignup(result):
            print('login failed')
            return EXITCODE_MUMBLE
        result = self.sget(s, addr, '/')
        if self.checkAddThing(result, parts[2]):
            print('flag not found in msg')
            return EXITCODE_CORRUPT

        return EXITCODE_OK

    def check(self, addr):
        return EXITCODE_OK


StrongboxChecker().run()
