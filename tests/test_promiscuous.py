#!/usr/bin/env python3

import unittest
import subprocess
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestPromiscuous(unittest.TestCase):

    def test_promiscuous(self):
        cmd = subprocess.Popen(['tcpdump', 's1'])
        p = ProcFinder()
        self.assertIn(cmd.pid, p.promiscuous_check())
        cmd.kill()

if __name__ == '__main__':
    unittest.main()
