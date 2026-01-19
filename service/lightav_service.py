import sys
import os

# Add project root to path so agent module can be found
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import threading

from agent.main_agent import main_loop


class LightAVService(win32serviceutil.ServiceFramework):
    _svc_name_ = "LightAVService"
    _svc_display_name_ = "LightAV Security Service"
    _svc_description_ = "Lightweight AI-based malware monitoring service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("LightAV Service started")
        self.main()

    def main(self):
        t = threading.Thread(target=main_loop)
        t.daemon = True
        t.start()

        while self.running:
            time.sleep(1)

        servicemanager.LogInfoMsg("LightAV Service stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(LightAVService)
