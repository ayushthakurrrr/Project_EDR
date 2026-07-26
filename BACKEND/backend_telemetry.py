import time, wmi, os
import pythoncom, psutil, winreg
import hashlib, shutil, tempfile, sqlite3
import win32api # registry sensor 
import queue
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import glob

PROCESS_STATUS = {}
PROCESS_LOCK = threading.Lock()


def update_process_status(pid, name, state):
    with PROCESS_LOCK:
        PROCESS_STATUS[str(pid)] = {
            "pid": pid,
            "process_name": name,
            "status": state,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    return

# Import shared resources from your upcoming utilities file
from backend_ipc import (
    event_queue,
    write_to_log_file, 
    debug_log, 
    get_next_event_id, 
    get_allow_list
)

from threat_detection import evaluate_threat_locally

# --- NEW: Forensic Caching Engine ---
# In-memory LRU-style Hash Cache: { file_path: (mtime, sha256_hash) }
HASH_CACHE = {}

def get_file_sha256(file_path):
    """
    Computes SHA256 hash with memory caching.
    Prevents high CPU/Disk usage when processes spawn frequently.
    """
    if not file_path or file_path == "Unknown" or not os.path.exists(file_path):
        return "Unknown"

    try:
        # Check current file modification time
        current_mtime = os.path.getmtime(file_path)

        # Return cached hash if file hasn't changed
        if file_path in HASH_CACHE:
            cached_mtime, cached_hash = HASH_CACHE[file_path]
            if cached_mtime == current_mtime:
                return cached_hash

        # Compute new hash if not in cache or modified
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        
        hash_value = sha256.hexdigest()

        # Update cache
        HASH_CACHE[file_path] = (current_mtime, hash_value)
        return hash_value

    except Exception:
        return "AccessDenied/Error"

# Create an async queue specifically for downloaded files needing processing
download_queue = queue.Queue()


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

            # --- NEW: Forensic Enrichment ---
            # 1. CAPTURE COMMAND LINE ARGUMENTS
            try:
                command_line = getattr(wmi_event, "CommandLine", None) or "Unknown"
            except:
                command_line = "Unknown"

            # 2. GET SHA256 HASH (USES CACHE AUTOMATICALLY)
            process_hash = get_file_sha256(executable_path)

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
                "command_line": command_line,  
                "sha256": process_hash,        
                "status": "RUNNING",
                "message": f"Process {process_name} (PID: {process_id}) spawned by {parent_name} (PID: {parent_id})."
            }

            # --- THREAT INTELLIGENCE CHECK ---
            payload = evaluate_threat_locally(payload)
            
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
            current_snapshot = set() # Create a fresh snapshot every loop
            connections = psutil.net_connections(kind='tcp')
            allow_list = get_allow_list()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    
                    if remote_ip in ("127.0.0.1", "::1"):
                        continue
                        
                    conn_key = (conn.pid, remote_ip, remote_port)
                    current_snapshot.add(conn_key) # Add alive connection to snapshot
                    
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
                            "status": "RUNNING",
                            "message": f"{proc_name} (PID: {conn.pid}) established connection to {remote_ip}:{remote_port}"
                        }

                        payload = evaluate_threat_locally(payload)    #<------threat intelligence check
                        
                        event_queue.put(payload)
                        write_to_log_file(payload)
            
        except Exception as e:
            debug_log(f"Network Monitor encountered an error: {e}")
        finally:
            # Overwrite old cache with current snapshot safely. Drops dead connections instantly!
            known_connections = current_snapshot
            
        time.sleep(2) 

def start_registry_monitor():
    """Background worker that watches for changes in startup Registry keys."""
    debug_log("Initializing Registry Persistence Monitor...")

    # Define OS constants missing from pywin32
    REG_NOTIFY_CHANGE_NAME = 0x00000001
    REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
    
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

    # Open handle to the key with NOTIFY permissions
    try:
        hKey = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, 
            run_key_path, 
            0, 
            winreg.KEY_READ | winreg.KEY_NOTIFY
        )
    except Exception as e:
        debug_log(f"Failed to open registry key for monitoring: {e}")
        return

    while True:
        try:
            # Blocking API Call. 0% CPU usage. Only wakes up when the OS detects a change.
            win32api.RegNotifyChangeKeyValue(
                hKey, 
                True, 
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, 
                None, 
                False
            )

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

                     payload = evaluate_threat_locally(payload)  #<------threat intelligence check
                
                     event_queue.put(payload)
                     write_to_log_file(payload)

            # Update baseline for the next differential check
            baseline = current_keys
            
        except Exception as e:
            debug_log(f"Registry Monitor encountered an error: {e}")
            time.sleep(5) # Fallback to prevent crash loops


class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        
        path = event.src_path
        normalized = os.path.normpath(path).lower()

        # Ignore Windows system profiles
        ignored_profiles = (
            r"c:\users\public",
            r"c:\users\default",
            r"c:\users\default user",
            r"c:\users\all users"
        )

        if normalized.startswith(ignored_profiles):
            return

        # Only process files created inside a Downloads folder
        parts = normalized.split(os.sep)
        if "downloads" not in parts:
            return

        # Skip temporary browser files
        if path.lower().endswith((".tmp", ".temp", ".crdownload", ".part", ".cache", ".log")):
            return

        # INSTANT ACTION: Put path in queue and return immediately!
        download_queue.put(path)



# Deduplication Cache: { file_path: last_processed_timestamp }
PROCESSED_DOWNLOADS = {}

def process_download_worker():
    """Background thread that safely waits for downloads to finish, deduplicates events, and hashes them."""
    global PROCESSED_DOWNLOADS

    while True:
        try:
            path = download_queue.get()
            
            # --- DEDUPLICATION CHECK ---
            current_time = time.time()
            
            # Clean up cache entries older than 60 seconds
            PROCESSED_DOWNLOADS = {
                p: t for p, t in PROCESSED_DOWNLOADS.items() 
                if current_time - t < 60
            }

            # If this file was already logged in the last 30 seconds, drop the duplicate!
            if path in PROCESSED_DOWNLOADS and (current_time - PROCESSED_DOWNLOADS[path]) < 30:
                download_queue.task_done()
                continue
            # --- END DEDUPLICATION CHECK ---

            # Wait 5 seconds for the browser to finalize writing the file to disk
            time.sleep(5)

            if not os.path.exists(path):
                download_queue.task_done()
                continue

            try:
                size = os.path.getsize(path)
                if size == 0:
                    download_queue.task_done()
                    continue
            except:
                download_queue.task_done()
                continue

            # Read Mark-of-the-Web (Zone.Identifier Alternate Data Stream) safely
            zone = None
            try:
                with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
                    zone = f.read()
            except:
                pass

            if not zone:
                download_queue.task_done()
                continue

            # Hash the completed download
            hash_value = get_file_sha256(path)

            payload = {
                "event_id": get_next_event_id(),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "DOWNLOAD_DETECTED",
                "file_name": os.path.basename(path),
                "path": path,
                "file_size": size,
                "sha256": hash_value,
                "zone_data": zone,
                "network_connections": len(psutil.net_connections("inet")),
                "message": f"Downloaded file detected: {os.path.basename(path)}"
            }

            # Record that this file has been processed
            PROCESSED_DOWNLOADS[path] = time.time()

            payload = evaluate_threat_locally(payload) #<------threat intelligence check
          
            event_queue.put(payload)
            write_to_log_file(payload)

        except Exception as e:
            debug_log(f"Error processing downloaded file: {e}")
            
        finally:
            download_queue.task_done()

def start_file_monitor():
    """Background worker that monitors all users' Downloads folders."""
    debug_log("Initializing File Download Monitor...")

    # Start the async processing worker in a background thread
    threading.Thread(target=process_download_worker, daemon=True).start()

    try:
        observer = Observer()

        # Monitor the entire Users directory
        observer.schedule(
            DownloadHandler(),
            r"C:\Users",
            recursive=True
        )

        debug_log("Watching C:\\Users recursively")

        observer.start()

        while True:
            time.sleep(1)

    except Exception as e:
        debug_log(f"Error in file monitor: {e}")

def start_software_monitor(event_queue=None):
    """
    Scans Windows registry uninstall paths for installed software 
    and pushes the payload to the event_queue.
    """
    debug_log("Initializing Software Monitor...")
    UNINSTALL_PATHS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    
    software_list = []
    
    for path in UNINSTALL_PATHS:
        root = winreg.HKEY_LOCAL_MACHINE

        try:
            key = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue

        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = path + "\\" + subkey_name
                
                try:
                    subkey = winreg.OpenKey(root, subkey_path)
                except FileNotFoundError:
                    i += 1
                    continue    

                try:
                    def get_value(name):
                        try:
                            value, _ = winreg.QueryValueEx(subkey, name)
                            return value
                        except FileNotFoundError:
                            return None    
                    
                    display_name = get_value("DisplayName")
                    
                    if display_name:
                        software = {
                            "display_name": display_name,
                            "version": get_value("DisplayVersion"),
                            "publisher": get_value("Publisher"),
                            "install_location": get_value("InstallLocation"),
                            "install_date": get_value("InstallDate"),
                        }
                        software_list.append(software)
                finally:
                    # Guarantees the handle is closed even if an exception occurs above
                    winreg.CloseKey(subkey)

            except OSError:
                # End of subkeys enumeration
                break

            i += 1
            
        winreg.CloseKey(key)

    print(f"Discovered {len(software_list)} installed applications.")
    
    payload = {
        "type": "SOFTWARE_LIST",
        "software_list": software_list
    }
    
    if event_queue:
        event_queue.put(payload)
    
    return payload
    
def start_system_monitor():
    """Background worker that logs system boot time and monitors user session switches/logins."""
    debug_log("Initializing System & User Session Monitor...")
    
    # 1. Capture and log System Boot Time once on startup
    try:
        boot_timestamp = psutil.boot_time()
        boot_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot_timestamp))
        
        boot_payload = {
            "event_id": get_next_event_id(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": "SYSTEM_BOOT_INFO",
            "boot_time": boot_time_str,
            "message": f"System last booted at {boot_time_str}"
        }
        
        event_queue.put(boot_payload)
        write_to_log_file(boot_payload)
    except Exception as e:
        debug_log(f"Error reading system boot time: {e}")

    # 2. Continuous User Session Monitoring Baseline
    known_users = set()

    while True:
        try:
            # Fetch set of currently logged-in desktop users
            current_users = {user.name for user in psutil.users()}
            
            # Detect new user sessions or switches
            new_users = current_users - known_users
            for username in new_users:
                payload = {
                    "event_id": get_next_event_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "USER_SESSION_STARTED",
                    "username": username,
                    "active_users": list(current_users),
                    "message": f"User session active/switched: {username}"
                }
                event_queue.put(payload)
                write_to_log_file(payload)

            # Detect disconnected user sessions
            ended_users = known_users - current_users
            for username in ended_users:
                payload = {
                    "event_id": get_next_event_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "USER_SESSION_ENDED",
                    "username": username,
                    "active_users": list(current_users),
                    "message": f"User session ended/logged out: {username}"
                }
                event_queue.put(payload)
                write_to_log_file(payload)

            # Update baseline snapshot
            known_users = current_users

        except Exception as e:
            debug_log(f"System/Session monitor encountered an error: {e}")

        # Poll every 5 seconds (0% CPU impact)
        time.sleep(5)