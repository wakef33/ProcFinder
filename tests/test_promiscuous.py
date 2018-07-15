#!/usr/bin/env python3

import unittest
import subprocess
import sys
from time import sleep
sys.path.append('..')
from procfinder import ProcFinder

class TestPromiscuous(unittest.TestCase):

    # TODO: Find quicker way than using tcpdump. Would eliminate need for sleep.
    def test_promiscuous(self):
        cmd = subprocess.Popen(['tcpdump', '-nqs1'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sleep(0.3)
        p = ProcFinder()
        self.assertIn(cmd.pid, p.promiscuous_check())
        cmd.kill()

if __name__ == '__main__':
    unittest.main()
