from hashlib import sha256


class Users(object):
    def __init__(self, filename):
        self.filename = filename
        try:
            self._users = {
                l.split(':')[1]: dict(zip(['uid', 'username', 'password'],
                                          l.strip().split(':')))
                for l in open(self.filename, 'r').readlines()
            }
        except FileNotFoundError:
            self._users = {}
            open(self.filename, 'w').write("")

    def auth(self, username, password):
        if username not in self._users:
            raise LookupError
        user = self._users[username]
        if user['password'] != sha256(password.encode("utf8")).hexdigest():
            raise KeyError
        return user['uid'], user['username']

    def __setitem__(self, key, value):
        if key in self._users or ':' in key:
            raise KeyError
        user = {'uid': hash(key), 'username': key,
                'password': sha256(value.encode("utf8")).hexdigest()}
        with open(self.filename, 'a') as db:
            self._users[key] = user
            db.write("%(uid)s:%(username)s:%(password)s\n" % user)
