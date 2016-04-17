#!/usr/bin/python3
# do stuff
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

    def checkAddItem(self, result, flag):
        try:
            item_content = result["page"].find('p',
                                               {'class': 'item__contetn'})
            if item_content.text.strip() == flag.strip():
                return False
            return True
        except (AttributeError, TypeError):
            return True

    def checkAddUser(self, result, flag):
        try:
            item_content = result["page"].find('h1',
                                               {'class': 'users__name'})

            if item_content.text.strip() == flag.strip():
                return False
            return True
        except (AttributeError, TypeError):
            return True

    def checkCheckroom(self, result, flag):
        try:
            item_content = result["page"].find('p',
                                               {'class': 'checkroom__content'})

            if item_content.text.strip() == flag.strip():
                return False
            return True
        except (AttributeError, TypeError):
            return True

    def put(self, addr, flag_id, flag, vuln):
        session = self.session(addr)
        user = self.randUser()
        item = self.randItem()
        checkroom = self.randCheckroom()
        checkrooms_id = 0
        user_id = 0
        item_id = 0
        if vuln == 1:
            user['user[name]'] = flag
        elif vuln == 2:
            item['item[content]'] = flag
        else:
            checkroom['checkroom[content]'] = flag
        result = self.spost(
            session, addr, 'checkrooms/new', 'checkrooms', checkroom
        )
        pars_url = urlparse(result['url'])
        not_checkrooms = not str(pars_url.path).startswith('/checkrooms/')

        if not result or not_checkrooms:
            print('add checkrooms  failed')
            return EXITCODE_MUMBLE
        try:
            checkrooms_id = int(pars_url.path.split('/')[-1])
        except ValueError:
            print('add checkrooms  failed')
            return EXITCODE_MUMBLE

        result = self.spost(session, addr, 'signup', 'users', user)
        check_user1 = self.checkSignup(result)
        pars_url = urlparse(result['url'])
        not_users = not str(pars_url.path).startswith('/users/')
        if not result or check_user1 or not_users:
            print('registration failed')
            return EXITCODE_MUMBLE
        try:
            user_id = int(pars_url.path.split('/')[-1])
        except ValueError:
            print('registration failed')
            return EXITCODE_MUMBLE

        result = self.spost(session, addr, '/strongbox?type=private', 'items',
                            item)
        pars_url = urlparse(result['url'])
        not_items = not str(pars_url.path).startswith('/items/')
        if not result or not_items:
            print('put items failed')
            return EXITCODE_MUMBLE
        try:
            item_id = int(pars_url.path.split('/')[-1])
        except ValueError:
            print('put items failed')
            return EXITCODE_MUMBLE
        print(
            '{}:{}:{}:{}:{}:{}'.format(
                user['user[email]'],
                user['user[password]'],
                checkrooms_id,
                user_id,
                item_id,
                checkroom['checkroom[secret]']
            )
        )
        return EXITCODE_OK

    def get(self, addr, flag_id, flag, vuln):
        s = self.session(addr)
        parts = flag_id.split(':', 6)
        user = {'session[email]': parts[0], 'session[password]': parts[1]}

        result = self.spost(s, addr, '/signin', 'sessions', user)

        if self.checkSignup(result):
            print('login failed')
            return EXITCODE_MUMBLE

        if vuln == 1:
            result = self.sget(s, addr, 'users/' + parts[3])
            if self.checkAddUser(result, flag):
                print('flag not found in user name')
                return EXITCODE_CORRUPT
        if vuln == 2:
            result = self.sget(s, addr, 'items/' + parts[4])
            if self.checkAddItem(result, flag):
                print('flag not found in thinf content')
                return EXITCODE_CORRUPT
        if vuln == 3:
            secret = {'secret': parts[5]}
            result = self.spost(s, addr,
                                'checkrooms/' + parts[2],
                                'checkrooms/' + parts[2],
                                secret)

            if self.checkCheckroom(result, flag):
                print('flag not found in thinf content')
                return EXITCODE_CORRUPT
        return EXITCODE_OK

    def check(self, addr):
        session = self.session(addr)
        user = self.randUser()
        item = self.randItem()
        checkrooms_id = 0
        checkroom = self.randCheckroom()
        result = self.spost(
            session, addr, 'checkrooms/new', 'checkrooms', checkroom
        )
        pars_url = urlparse(result['url'])
        checkrooms_path = pars_url.path

        try:
            checkrooms_id = int(checkrooms_path.split('/')[-1])
        except ValueError:
            print('add checkrooms  failed 1')
            return EXITCODE_MUMBLE
        result = self.spost(
            session, addr,
            'checkrooms/' + str(checkrooms_id),
            'checkrooms/' + str(checkrooms_id),
            {'secret': checkroom['checkroom[secret]']}
        )
        if self.checkCheckroom(result, checkroom['checkroom[content]']):
            print('add checkrooms  failed 2')
            return EXITCODE_MUMBLE
        result = self.sget(session, addr,'strongbox?type=public')
        if not result['page'].findAll(text=checkroom['checkroom[name]']):
            print('not found strongbox public')
            return EXITCODE_MUMBLE

        result = self.spost(session, addr, 'signup', 'users', user)
        check_user1 = self.checkSignup(result)
        pars_url = urlparse(result['url'])
        not_users = not str(pars_url.path).startswith('/users/')
        if not result or check_user1 or not_users:
            print('registration failed')
            return EXITCODE_MUMBLE
        try:
            user_id = int(pars_url.path.split('/')[-1])
        except ValueError:
            print('registration failed')
            return EXITCODE_MUMBLE
        result = self.spost(session, addr, '/strongbox?type=private', 'items',
                            item)
        pars_url = urlparse(result['url'])
        not_items = not str(pars_url.path).startswith('/items/')
        if not result or not_items:
            print('put items failed')
            return EXITCODE_MUMBLE
        try:
            item_id = int(pars_url.path.split('/')[-1])
        except ValueError:
            print('put items failed')
            return EXITCODE_MUMBLE
        result = self.sget(session, addr,'strongbox?type=private')
        if not result['page'].findAll(text=item['item[title]']):
            print('not found strongbox public')
            return EXITCODE_MUMBLE

        return EXITCODE_OK


StrongboxChecker().run()
