#!/usr/bin/env python3

import unittest
from subprocess import Popen
from sys import path
path.append('..')
from procfinder import ProcFinder

class TestCWD(unittest.TestCase):

    def test_cwd(self):
        cmd_tmp = Popen(['sleep', '600'], cwd='/tmp')
        cmd_shm = Popen(['sleep', '600'], cwd='/dev/shm')
        cmd_var = Popen(['sleep', '600'], cwd='/var/tmp')
        cwd_list = [cmd_tmp.pid, cmd_shm.pid, cmd_var.pid]
        p = ProcFinder()
        for i in cwd_list:
            self.assertIn(i, p.cwd_check())
        cmd_tmp.kill()
        cmd_shm.kill()
        cmd_var.kill()

if __name__ == '__main__':
    unittest.main()
