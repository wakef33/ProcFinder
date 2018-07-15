#!/usr/bin/env python3

import unittest
import sys
sys.path.append('..')
from procfinder import ProcFinder

class TestProcFinder(unittest.TestCase):

    def test_proc_finder_creation(self):
        p = ProcFinder()        
        self.assertIsInstance(p, ProcFinder)

if __name__ == '__main__':
    unittest.main()
