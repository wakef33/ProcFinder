#!/usr/bin/env python3

import unittest
from socket import socket, AF_PACKET, SOCK_RAW
from os import getpid
from sys import path
path.append('..')
from procfinder import ProcFinder

class TestPromiscuous(unittest.TestCase):

    def test_promiscuous(self):
        s = socket(AF_PACKET , SOCK_RAW)
        p = ProcFinder()
        self.assertIn(getpid(), p.promiscuous_check())
        s.close()

if __name__ == '__main__':
    unittest.main()
