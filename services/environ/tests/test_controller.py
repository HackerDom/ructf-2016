# coding=utf-8
from unittest import TestCase
from os import remove
import controller
__author__ = 'm_messiah'


class TestController(TestCase):
    def setUp(self):
        controller.app.config['TESTING'] = True
        self.app = controller.app.test_client(use_cookies=True)
        self.app.application.users = controller.Users("tests/test_users.db")
        self.app.application.users["admin"] = "qwerty"

    def tearDown(self):
        del self.app.application.users._users["admin"]
        remove("tests/test_users.db")

    def test_dashboard(self):
        resp = self.app.get("/")
        self.assertIn(b"36.6", resp.data)

    def test_register(self):
        self.assertIn(b"Registration", self.app.get("/register").data)
        post = self.app.post("/register", data={'username': "admin1",
                                                'password': "qwerty1"},
                             follow_redirects=True).data
        self.assertIn(b"Registration successful! Please log in.", post)

    def test_login(self):
        self.assertIn(b"Login", self.app.get("/login").data)
        post = self.app.post("/login", data={'username': "admin",
                                             'password': "qwerty"},
                             follow_redirects=True).data
        self.assertIn(b"admin", post)
        self.assertIn(b"Since", post)

    def test_log(self):
        self.app.post("/login", data={'username': "admin",
                                      'password': "qwerty"},
                      follow_redirects=True)
        self.assertIn(b"Log for temperature",
                      self.app.get("/log/temperature").data)

    def test_tail(self):
        self.assertIn("app.run", controller.tail("../controller.py"))