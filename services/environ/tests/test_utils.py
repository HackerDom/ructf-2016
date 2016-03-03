from unittest import TestCase
import utils


class TestUtils(TestCase):
    def test_xor(self):
        self.assertEqual(b'HwoeAAs=', utils.xor("hello", "world"))

    def test_tail(self):
        self.assertIn('app.run(', utils.tail("controller.py"))