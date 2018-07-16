#!/usr/bin/env python3

import unittest
from subprocess import Popen
from sys import path
path.append('..')
from procfinder import ProcFinder

class TestDeleted(unittest.TestCase):

    def test_deleted(self):
        cmd_cp = Popen(['cp', '/bin/sleep', '/tmp/deleted'])
        cmd_cp.communicate()
        cmd_run = Popen(['/tmp/deleted', '600'])
        cmd_del = Popen(['rm', '-f', '/tmp/deleted'])
        p = ProcFinder()
        self.assertIn(cmd_run.pid, p.deleted_check())
        cmd_run.kill()

if __name__ == '__main__':
    unittest.main()
