#!/usr/bin/python3
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
        response = s.get(self.url(addr, suffix_get))
        auth_token_page = self.parseresponse(response)
        auth_token = auth_token_page["page"].find(
            "input", {"name": "authenticity_token"}
        )
        csrf_data = auth_token.get("value")
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

    def checkAddThing(self, result, flag):
        try:
            thing_content = result["page"].find('p',
                                                {'class': 'thing__contetn'})
            if thing_content.text.strip() == flag:
                return False
            return True
        except (AttributeError, TypeError):
            return True

    def checkAddUser(self, result, flag):
        try:
            thing_content = result["page"].find('h1',
                                                {'class': 'users__name'})
            if thing_content.text.strip() == flag:
                return False
            return True
        except (AttributeError, TypeError):
            return True

    def put(self, addr, flag_id, flag, vuln):
        session = self.session(addr)
        user = self.randUser()
        thing = self.randThing()
        if vuln == 1:
            user['user[name]'] = flag
        if vuln == 2:
            thing['thing[content]'] = flag
        result = self.spost(session, addr, 'signup', 'users', user)
        check_user1 = self.checkSignup(result)
        check_user2 = self.checkAddUser(result, user['user[name]'])
        if not result or check_user1 or check_user2:
            print('registration failed')
            return EXITCODE_MUMBLE
        user_id = result['url'].split('/')[-1]
        result = self.spost(session, addr, '/', '/things', thing)
        if self.checkAddThing(result, thing['thing[content]']):
            print('put msg failed')
            return EXITCODE_MUMBLE
        thing_id = result['url'].split('/')[-1]
        print(
            '{}:{}:{}:{}'.format(
                user['user[email]'],
                user['user[password]'],
                user_id,
                thing_id
            )
        )
        return EXITCODE_OK

    def get(self, addr, flag_id, flag, vuln):
        s = self.session(addr)
        parts = flag_id.split(':', 4)
        user = {'session[email]': parts[0], 'session[password]': parts[1]}

        result = self.spost(s, addr, '/signin', 'sessions', user)

        if self.checkSignup(result):
            print('login failed')
            return EXITCODE_MUMBLE

        if vuln == 1:
            result['page'].find_all()
            result = self.sget(s, addr, '/users/' + parts[2])
            if self.checkAddThing(result, flag):
                print('flag not found in user name')
                return EXITCODE_CORRUPT
        if vuln == 2:
            result = self.sget(s, addr, '/things/' + parts[3])
            if self.checkAddThing(result, flag):
                print('flag not found in thinf content')
                return EXITCODE_CORRUPT

        return EXITCODE_OK


    def check(self, addr):
        return EXITCODE_OK


StrongboxChecker().run()
