#!/usr/bin/env python3
"""
Quick test runner for Phase 2
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Now run the test
from tests.test_phase2 import run_all_tests
import sys

success = run_all_tests()
sys.exit(0 if success else 1)
