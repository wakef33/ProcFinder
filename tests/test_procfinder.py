import unittest
from procfinder import ProcFinder

class TestProcFinder(unittest.TestCase):

    def test_proc_finder_creation(self):
        p = ProcFinder()
        self.assertIsInstance(p, ProcFinder)
