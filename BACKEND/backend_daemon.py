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
from collections import defaultdict  # <--- NEW: Required to group files by date
import win32pipe
import win32file
import pywintypes
import json
import psutil


# Import your newly separated modules
from backend_ipc import start_ipc_server, get_next_event_id, event_queue,write_to_log_file
from backend_telemetry import (
    start_wmi_monitor, 
    start_file_monitor, 
    start_network_monitor, 
    start_registry_monitor,
    start_software_monitor,
    start_system_monitor,
)

# ---> ADD THIS LINE <---
from threat_detection import start_threat_intel_updater

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

def kill_process(pid):
    try:
        process = psutil.Process(int(pid))

        process.kill()
        process_name = process.name()

        return {
    "success": True,
    "pid": pid,
    "result": "KILLED",
    "state": "KILLED"
}

    except Exception as e:
        print("[KILL ERROR]", e)
        return {
            "success": False,
            "pid": pid,
            "error": str(e)
        }
def stop_process(pid):
    try:
        process = psutil.Process(int(pid))

        process.terminate()
        process_name = process.name()

        return {
            "success": True,
            "pid": pid,
            "result": "STOPPED",
            "state": "STOPPED"
        }

    except Exception as e:
        return {
            "success": False,
            "pid": pid,
            "error": str(e)
        }


def restart_process(pid):
    try:
        process = psutil.Process(int(pid))

        old_name = process.name()
        exe = process.exe()

        process.kill()

        time.sleep(1)

        new_process = psutil.Popen(exe)

        return {
            "success": True,
            "old_pid": pid,
            "new_pid": new_process.pid,
            "result": "PROCESS_RESTARTED",
            "state": "RUNNING"
        }

    except Exception as e:
        return {
            "success": False,
            "pid": pid,
            "error": str(e)
        }

    
def listen_for_commands(event_queue):
    """
    Dedicated thread to listen for incoming commands from the PyQt GUI.
    It reads from a separate pipe so it never blocks outgoing telemetry.
    """
    pipe_name = r'\\.\pipe\EDR_Commands'
    
    while True:
        try:
            # Create the Command Pipe (Server Side)
            # PIPE_ACCESS_INBOUND ensures the backend can only READ from this pipe.
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_INBOUND, 
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536,
                0,
                None
            )
            
            print(f"[Command Thread] Waiting for GUI to connect to {pipe_name}...")
            win32pipe.ConnectNamedPipe(pipe, None)
            print("[Command Thread] GUI connected. Listening...")
            
            while True:
                try:
                    # This is a synchronous, blocking read. 
                    # It will sit here safely until the GUI writes to the pipe.
                    result, data = win32file.ReadFile(pipe, 64000)
                    
                    if data:
                        command_str = data.decode('utf-8')
                        command_dict = json.loads(command_str)
                        
                        action = command_dict.get("action")
                        response = None
                        
                        # Route the incoming commands
                        # if action == "REFRESH_SOFTWARE":
                        #     print("[Command Thread] Received REFRESH_SOFTWARE command from GUI.")
                            
                        #     # Trigger your software scanner!
                        #     # It will scan the registry and drop the payload directly into event_queue
                        #     start_software_monitor(event_queue)
                        if action == "REFRESH_SOFTWARE":
                           print(  "[Command Thread] REFRESH_SOFTWARE")
                           start_software_monitor(event_queue)

                        elif action == "KILL_PROCESS":
                           pid = command_dict.get("pid")
                           print(f"[Command Thread] Kill PID {pid}")
                           response = kill_process(pid)


                        elif action == "STOP_PROCESS":
                           pid = command_dict.get("pid")
                           print(f"[Command Thread] Stop PID {pid}")
                           response = stop_process(pid)


                        elif action == "RESTART_PROCESS":
                           pid = command_dict.get("pid")
                           print(f"[Command Thread] Restart PID {pid}")
                           response = restart_process(pid)  


                        if response:

                            incident_payload = {
                           "event_id": get_next_event_id(),
                           "type": "INCIDENT_RESPONSE",
                           "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                           "action": action,
                            "pid": str(command_dict.get("pid")),
                            # "status": "SUCCESS" if response.get("success") else "FAILED",
                                "status": response.get("result") if response.get("success") else "FAILED",
                            "message": response.get(
                            "result",
                             response.get("error", "UNKNOWN")
                            )}

                            print("[BACKEND] Sending incident response:")
                            print(json.dumps(incident_payload, indent=4))

                            # Send to GUI
                            event_queue.put(incident_payload)
                            # Write into log
                            write_to_log_file(incident_payload)

                            
                          
                except pywintypes.error as e:
                    # Error 109 means the GUI disconnected (e.g., app was closed)
                    if e.args[0] == 109: 
                        print("[Command Thread] GUI disconnected. Restarting pipe...")
                        break 
                    else:
                        print(f"[Command Thread] Read error: {e}")
                        break

                        
        except Exception as e:
            print(f"[Command Thread] Pipe creation error: {e}")
            time.sleep(2) # Brief pause before retrying to prevent CPU spinning
            
        finally:
            # Always clean up the handle before looping back to create a new one
            try:
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)
            except:
                pass

def archive_logs():
    """Archives old logs into a zip file, merging same-day logs into a single file."""
    logs = sorted(
        [
            f for f in os.listdir(BASE) 
             if f.startswith("agent_") and f.endswith(".log")
        ],
        key=lambda f: os.path.getmtime(os.path.join(BASE, f))
    )
    
    if len(logs) > 7:
        # Group candidate archive logs by their date prefix (YYYY-MM-DD)
        logs_by_date = defaultdict(list)
        for f in logs[:-7]:
            # Extracts 'YYYY-MM-DD' from 'agent_YYYY-MM-DD.log' or 'agent_YYYY-MM-DD_HH-MM-SS.log'
            log_date = f.replace("agent_", "").split("_")[0].replace(".log", "")
            logs_by_date[log_date].append(f)

        # Generate the timestamp dynamically when the zip is created
        zip_name = os.path.join(ARCHIVE, f"old_logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.zip")
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as z:
            for log_date, file_list in logs_by_date.items():
                # Sort the day's files chronologically so log events stay in order
                file_list.sort(key=lambda f: os.path.getmtime(os.path.join(BASE, f)))
                
                merged_content = ""
                for f in file_list:
                    p = os.path.join(BASE, f)
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as infile:
                            merged_content += infile.read() + "\n"
                        # Remove the rotated file from disk once read
                        os.remove(p)
                    except Exception as e:
                        logger.error(f"Error reading/removing {f} during archiving: {e}")
                
                # Write the merged text directly into the archive as 'YYYY-MM-DD_edr_log.log'
                if merged_content.strip():
                    merged_filename = f"{log_date}_edr_log.log"
                    z.writestr(merged_filename, merged_content)

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
    _svc_name_ = "SimpleEDR1"
    _svc_display_name_ = "Simple EDR Daemon_1"
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
        # ---> ADD THIS LINE <---
        start_threat_intel_updater()

        # 2. Start Data Engines (Dev's Monitors & Raj's File Monitor)
        threading.Thread(target=start_wmi_monitor, daemon=True).start()
        threading.Thread(target=start_network_monitor, daemon=True).start()
        threading.Thread(target=start_registry_monitor, daemon=True).start()
        threading.Thread(target=start_file_monitor, daemon=True).start()
        # threading.Thread(target=start_software_monitor, daemon=True).start()
        threading.Thread(target=listen_for_commands, args=(event_queue,), daemon=True).start()

        threading.Thread(target=start_system_monitor, daemon=True).start()
        # Keep service running until stopped
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

def run_standalone():
    """Bypasses Windows Services so you can test directly in VS Code"""
    print("Running in VS Code Test Mode... (Bypassing Windows Service)")
    
    threading.Thread(target=start_ipc_server, daemon=True).start()
    threading.Thread(target=archive_worker, daemon=True).start()
    # ---> ADD THIS LINE <---
    start_threat_intel_updater()
    threading.Thread(target=start_wmi_monitor, daemon=True).start()
    threading.Thread(target=start_network_monitor, daemon=True).start()
    threading.Thread(target=start_registry_monitor, daemon=True).start()
    threading.Thread(target=start_file_monitor, daemon=True).start()
    # threading.Thread(target=start_software_monitor, daemon=True).start()
    threading.Thread(target=listen_for_commands, args=(event_queue,), daemon=True).start()
    threading.Thread(target=start_system_monitor, daemon=True).start()
     
    # Keep script alive
    while True:
        time.sleep(1)

if __name__ == '__main__':
    # 1. VS Code Test Mode
    if "--test" in sys.argv:
        run_standalone()

    elif len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRService)
        servicemanager.StartServiceCtrlDispatcher()

    else:
        import win32serviceutil
        win32serviceutil.HandleCommandLine(EDRService)