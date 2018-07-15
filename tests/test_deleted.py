#!/usr/bin/env python3

import unittest
import subprocess
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestDeleted(unittest.TestCase):

    def test_deleted(self):
        cmd_cp = subprocess.Popen(['cp', '/bin/sleep', '/tmp/deleted'])
        cmd_cp.communicate()
        cmd_run = subprocess.Popen(['/tmp/deleted', '600'])
        cmd_del = subprocess.Popen(['rm', '-f', '/tmp/deleted'])
        p = ProcFinder()
        self.assertIn(str(cmd_run.pid), p.deleted_check())
        cmd_run.kill()

if __name__ == '__main__':
    unittest.main()
