#!/usr/bin/env python3

import unittest
import subprocess
import os
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestPreload(unittest.TestCase):

    def test_preload(self):
        os.environ["LD_PRELOAD"] = "/lib/x86_64-linux-gnu/libcrypt-2.23.so"
        cmd = subprocess.Popen(['sleep', '600'])
        p = ProcFinder()
        self.assertIn(cmd.pid, p.preload_check())
        cmd.kill()

if __name__ == '__main__':
    unittest.main()
