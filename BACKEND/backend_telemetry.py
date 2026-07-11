import time ,wmi,os
import pythoncom ,psutil, winreg
import hashlib,shutil,tempfile,sqlite3

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import shared resources from your upcoming utilities file
from backend_ipc import (
    event_queue ,
    write_to_log_file, 
    debug_log, 
    get_next_event_id, 
    get_allow_list
)

def start_wmi_monitor():
    """Background worker that listens for Windows process creation events (Event-Driven)."""
    debug_log("Initializing WMI Process Monitor...")
    pythoncom.CoInitialize() # Required for WMI in background threads
    
    try:
        c = wmi.WMI()
        watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process", delay_secs=1)
        
        while True:
            wmi_event = watcher()
            process_name = wmi_event.Name
            
            # Fetch the dynamic allow-list
            allow_list = get_allow_list()
            
            # Drop event if process is in allow-list
            if process_name.lower() in allow_list:
                continue

            process_id = wmi_event.ProcessId
            parent_id = wmi_event.ParentProcessId
            
            # Resolve Parent Process Name safely
            parent_name = "Unknown"
            if parent_id:
                try:
                    parent_name = psutil.Process(parent_id).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "Unknown/Terminated"
            
            try:
                executable_path = wmi_event.ExecutablePath or "Unknown"
            except:
                executable_path = "Unknown"

            # UAC and Installer Detection
            lower_name = process_name.lower()
            event_type = "PROCESS_CREATION"
            
            if lower_name == "consent.exe":
                event_type = "UAC_DETECTED"
            elif "setup" in lower_name or "install" in lower_name or lower_name.endswith(".msi"):
                event_type = "INSTALLER_DETECTED"

            payload = {
                "event_id": get_next_event_id(),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "type": event_type,
                "process_name": process_name,
                "pid": process_id,
                "parent_name": parent_name,
                "parent_pid": parent_id,
                "path": executable_path,
                "message": f"Process {process_name} (PID: {process_id}) spawned by {parent_name} (PID: {parent_id})."
            }
            
            event_queue.put(payload)
            write_to_log_file(payload)
            
    except Exception as e:
        debug_log(f"WMI Monitor encountered an error: {e}")

def start_network_monitor():
    """Background worker that polls for active network connections via TCP."""
    debug_log("Initializing Network Socket Monitor...")
    known_connections = set() 
    
    while True:
        try:
            connections = psutil.net_connections(kind='tcp')
            allow_list = get_allow_list()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    
                    if remote_ip in ("127.0.0.1", "::1"):
                        continue
                        
                    conn_key = (conn.pid, remote_ip, remote_port)
                    
                    if conn_key not in known_connections:
                        known_connections.add(conn_key)
                        
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "Unknown/Terminated"

                        # Drop event if process is in allow-list
                        if proc_name.lower() in allow_list:
                            continue

                        payload = {
                            "event_id": get_next_event_id(),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "NETWORK_CONNECTION",
                            "process_name": proc_name,
                            "pid": conn.pid,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "local_port": conn.laddr.port,
                            "message": f"{proc_name} (PID: {conn.pid}) established connection to {remote_ip}:{remote_port}"
                        }
                        
                        event_queue.put(payload)
                        write_to_log_file(payload)
                        
        except Exception as e:
            debug_log(f"Network Monitor encountered an error: {e}")
            
        time.sleep(2) 

def start_registry_monitor():
    """Background worker that watches for changes in startup Registry keys."""
    debug_log("Initializing Registry Persistence Monitor...")
    
    run_key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    def get_run_keys():
        keys = {}
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, run_key_path, 0, winreg.KEY_READ) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    keys[name] = value
        except Exception:
            pass
        return keys

    baseline = get_run_keys()

    while True:
        time.sleep(5)
        current_keys = get_run_keys()
        
        for name, value in current_keys.items():
            if name not in baseline or baseline[name] != value:
                payload = {
                    "event_id": get_next_event_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "PERSISTENCE_DETECTED",
                    "reg_path": f"HKLM\\{run_key_path}",
                    "key_name": name,
                    "key_value": value,
                    "message": f"Suspicious Registry Run key added: {name} -> {value}"
                }
                
                event_queue.put(payload)
                write_to_log_file(payload)
                baseline[name] = value

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):

        if event.is_directory:
            return
        path = event.src_path
        if path.lower().endswith((".tmp", ".temp", ".crdownload", ".part", ".cache", ".log")):
            return
        time.sleep(10)

        try:
            if not os.path.exists(path):
                return
            size = os.path.getsize(path)
            if size == 0:
                return
        except:
            return
        
        zone = None
        try:
            with open(path + ":Zone.Identifier") as f:
                zone = f.read()
        except:
            pass


        if not zone :
            return

        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(8192), b""):
                    sha.update(block)
            hash_value = sha.hexdigest()
        except:
            hash_value = None

        payload = {
    "event_id": get_next_event_id(),
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "type": "DOWNLOAD_DETECTED",
    "file_name": os.path.basename(path),
    "file_path": path,
    "file_size": size,
    "sha256": hash_value,
    "zone_data":zone,
    "network_connections" :len(psutil.net_connections("inet")),
    "message": f"Downloaded file detected: {os.path.basename(path)}"
        }
        print(payload)
        event_queue.put(payload)
        write_to_log_file(payload)

def start_file_monitor():
    """Background worker that monitors the Downloads folder for newly downloaded files."""
    debug_log("Initializing File Download Monitor...")

    try:
        download_folder = os.path.join(os.environ["USERPROFILE"], "Downloads")

        if not os.path.exists(download_folder):
            debug_log(f"Downloads folder not found: {download_folder}")
            return

        observer = Observer()
        observer.schedule(
            DownloadHandler(),
            download_folder,
            recursive=False
        )

        observer.start()
        debug_log(f"Watching folder: {download_folder}")

        while True:
            time.sleep(1)

    except Exception as e:
        debug_log(f"File Monitor encountered an error: {e}")

    finally:
        try:
            observer.stop()
            observer.join()
        except:
            pass
    
