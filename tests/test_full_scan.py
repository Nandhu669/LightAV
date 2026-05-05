import os
import unittest
from unittest.mock import patch, MagicMock
from agent.scanner import Verdict

# We'll mock psutil and os.walk to test the server logic
# Since server.py is a FastAPI app, we can test the logic directly or through the app

class TestFullScanLogic(unittest.TestCase):



    def test_psutil_and_walk_integration(self):
        # Verify that we can actually call psutil
        import psutil
        drives = [p.mountpoint for p in psutil.disk_partitions() if 'fixed' in p.opts or 'cdrom' not in p.opts.lower()]
        print(f"Detected drives: {drives}")
        self.assertGreater(len(drives), 0)



if __name__ == '__main__':
    unittest.main()
