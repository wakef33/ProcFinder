#!/usr/bin/env python3

import unittest
from sys import path
path.append('..')
from procfinder import ProcFinder

class TestProcFinder(unittest.TestCase):

    def test_procfinder_creation(self):
        p = ProcFinder()        
        self.assertIsInstance(p, ProcFinder)

if __name__ == '__main__':
    unittest.main()
