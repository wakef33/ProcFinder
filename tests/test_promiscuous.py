#!/usr/bin/env python3

import unittest
import socket
import os
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestPromiscuous(unittest.TestCase):

    def test_promiscuous(self):
        s = socket.socket(socket.AF_PACKET , socket.SOCK_RAW)
        p = ProcFinder()
        self.assertIn(os.getpid(), p.promiscuous_check())
        s.close()

if __name__ == '__main__':
    unittest.main()
