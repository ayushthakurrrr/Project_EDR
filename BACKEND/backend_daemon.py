import os
import logging
import zipfile
import threading
import time
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
from datetime import datetime
import win32timezone

# Import your newly separated modules
from backend_ipc import start_ipc_server, get_next_event_id
from backend_telemetry import (
    start_wmi_monitor, 
    start_file_monitor, 
    start_network_monitor, 
    start_registry_monitor,
    start_software_monitor
)

# Define paths and logging
BASE = os.path.join(os.getenv("PROGRAMDATA", r"C:\ProgramData"), "EdrAgent")
ARCHIVE = os.path.join(BASE, "archive")
os.makedirs(ARCHIVE, exist_ok=True)

logger = logging.getLogger("EDR")
logger.setLevel(logging.INFO)
MAX_SIZE = 1024*1024

class DailySizeHandler(logging.Handler):
    def emit(self,record):
        try:
            date = datetime.now().strftime("%Y-%m-%d")
            log_file = os.path.join(BASE,f"agent_{date}.log")

            if os.path.exists(log_file) and os.path.getsize(log_file) >= MAX_SIZE:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                rotated = os.path.join(BASE,f"agent_{timestamp}.log")
                
                if not os.path.exists(rotated):
                    os.rename(log_file,rotated)
            with open(log_file,"a",encoding="utf-8") as f:
                f.write(self.format(record)+"\n")
        except Exception:
            self.handleError(record)

h = DailySizeHandler()
h.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
logger.addHandler(h)

def archive_logs():
    """Archives old logs into a zip file to save space."""
    logs = sorted(
        [
            f for f in os.listdir(BASE) 
             if f.startswith("agent_") and f.endswith(".log")
        ],
        key=lambda f:os.path.getmtime(os.path.join(BASE,f))
        )
    
    if len(logs) > 7:
        # Generate the timestamp dynamically when the zip is created
        zip_name = os.path.join(ARCHIVE, f"old_logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.zip")
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as z:
            for f in logs[:-7]:
                p = os.path.join(BASE, f)
                z.write(p, f)
                os.remove(p)

def archive_worker():
    """Background thread to periodically check and archive old logs."""
    while True:
        try:
            archive_logs()
        except Exception as e:
            logger.error(f"Archiving error: {e}")
        time.sleep(60)  # Check every 60 seconds

# Service_wrapper_class
class EDRService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SimpleEDR 1"
    _svc_display_name_ = "Simple EDR Daemon 1"
    _svc_description_ = "Background telemetry engine for EDR"

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        # 1. Start core utilities (IPC Named Pipe & Log Archiver)
        threading.Thread(target=start_ipc_server, daemon=True).start()
        threading.Thread(target=archive_worker, daemon=True).start()

        # 2. Start Data Engines (Your Monitors & Raj's File Monitor)
        threading.Thread(target=start_wmi_monitor, daemon=True).start()
        threading.Thread(target=start_network_monitor, daemon=True).start()
        threading.Thread(target=start_registry_monitor, daemon=True).start()
        threading.Thread(target=start_file_monitor, daemon=True).start()
        threading.Thread(target=start_software_monitor, daemon=True).start()
        # Keep service running until stopped
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

def run_standalone():
    """Bypasses Windows Services so you can test directly in VS Code"""
    print("Running in VS Code Test Mode... (Bypassing Windows Service)")
    
    threading.Thread(target=start_ipc_server, daemon=True).start()
    threading.Thread(target=archive_worker, daemon=True).start()
    threading.Thread(target=start_wmi_monitor, daemon=True).start()
    threading.Thread(target=start_network_monitor, daemon=True).start()
    threading.Thread(target=start_registry_monitor, daemon=True).start()
    threading.Thread(target=start_file_monitor, daemon=True).start()
    threading.Thread(target=start_software_monitor, daemon=True).start()
     
    # Keep script alive
    while True:
        time.sleep(1)

if __name__ == '__main__':
    if "--test" in sys.argv:
        run_standalone()
    else:
        win32serviceutil.HandleCommandLine(EDRService)