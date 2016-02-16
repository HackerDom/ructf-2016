# coding=utf-8
from unittest import TestCase
import controller
__author__ = 'm_messiah'


class TestController(TestCase):
    def setUp(self):
        controller.app.config['TESTING'] = True
        self.app = controller.app.test_client(use_cookies=True)

    def test_dashboard(self):
        resp = self.app.get("/")
        print(resp.data)
        self.assertIn(b"36.6", resp.data)

    def test_register(self):
        self.assertIn(b"Registration", self.app.get("/register").data)

    def test_login(self):
        self.assertIn(b"Login", self.app.get("/login").data)

    def test_log(self):
        print(self.app.get("/log/temperature").data)
        self.assertIn(b"log", self.app.get("/log/temperature").data)

    def test_tail(self):
        self.assertIn("app.run()", controller.tail("../controller.py"))