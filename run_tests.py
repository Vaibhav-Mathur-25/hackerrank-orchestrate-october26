"""Portable standard-library test runner; challenge integration is opt-in."""
import sys
import unittest
from pathlib import Path

root = Path(__file__).resolve().parent
sys.path[:0] = [str(root / 'code'), str(root / 'code/tests')]
suite = unittest.defaultTestLoader.discover(str(root / 'code/tests'))
raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
