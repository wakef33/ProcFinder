#!/usr/bin/env python3

import unittest
from subprocess import Popen
from os import environ
from sys import path
path.append('..')
from procfinder import ProcFinder

class TestPath(unittest.TestCase):

    def test_path(self):
        environ["PATH"] = environ["PATH"] + ":."
        cmd = Popen(['sleep', '600'])
        p = ProcFinder()
        self.assertIn(cmd.pid, p.path_check())
        cmd.kill()

if __name__ == '__main__':
    unittest.main()
