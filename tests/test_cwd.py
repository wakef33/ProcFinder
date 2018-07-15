#!/usr/bin/env python3

import unittest
import subprocess
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestCWD(unittest.TestCase):

    def test_cwd(self):
        cmd_tmp = subprocess.Popen(['sleep', '600'], cwd='/tmp')
        cmd_shm = subprocess.Popen(['sleep', '600'], cwd='/dev/shm')
        cmd_var = subprocess.Popen(['sleep', '600'], cwd='/var/tmp')
        cwd_list = [cmd_tmp.pid, cmd_shm.pid, cmd_var.pid]
        p = ProcFinder()
        for i in cwd_list:
            self.assertIn(i, p.cwd_check())
        cmd_tmp.kill()
        cmd_shm.kill()
        cmd_var.kill()

if __name__ == '__main__':
    unittest.main()
