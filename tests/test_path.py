#!/usr/bin/env python3

import unittest
import subprocess
import os
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestPath(unittest.TestCase):

    def test_path(self):
        os.environ["PATH"] = os.environ["PATH"] + ":."
        cmd = subprocess.Popen(['sleep', '600'])
        p = ProcFinder()
        self.assertIn(cmd.pid, p.path_check())
        cmd.kill()

if __name__ == '__main__':
    unittest.main()
