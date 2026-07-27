import json
import queue
import threading
import win32pipe
import win32file
import win32security
import logging
import winerror
import win32api
from logging.handlers import RotatingFileHandler
import psutil       # <-- NEW
import datetime     # <-- NEW

PIPE_NAME = r'\\.\pipe\SimpleEDRPipe1'

# Shared Global State (Thread-Safe)
event_queue = queue.Queue()
event_counter = 1
counter_lock = threading.Lock()
ALLOW_LIST = set()

def write_to_log_file(payload):
    """Uses Raj's global logger to write telemetry to agent.log"""
    logger = logging.getLogger("EDR")
    if logger.handlers:
        logger.info(json.dumps(payload))
    

def debug_log(message):
    """Uses Raj's global logger to record internal errors"""
    logger = logging.getLogger("EDR")
    logger.error(message)
    
def get_allow_list():
    """Returns the current allow-list for telemetry filtering"""
    return ALLOW_LIST.copy()

def get_next_event_id():
    """Generates a thread-safe incrementing ID."""
    global event_counter
    with counter_lock:
        current_id = event_counter
        event_counter += 1
        return current_id

def create_named_pipe():
    """Configures security attributes and opens the Windows Named Pipe."""
    sa = win32security.SECURITY_ATTRIBUTES()
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.Initialize()
    sd.SetSecurityDescriptorDacl(True, None, False)
    sa.SECURITY_DESCRIPTOR = sd
    sa.bInheritHandle = False
    
    return win32pipe.CreateNamedPipe(
        PIPE_NAME,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
    )

clients = []
clients_lock = threading.Lock()

def send_initial_state(pipe_handle):
    """Sends current Boot Time and Active Users down the pipe as soon as GUI connects."""
    try:
        # --- NEW: Get the current time for the table's timestamp column ---
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 1. Fetch & Send Boot Time
        boot_ts = psutil.boot_time()
        boot_time_str = datetime.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S")
        
        boot_payload = json.dumps({
            "timestamp": current_time_str,
            "type": "SYSTEM_BOOT_INFO",
            "boot_time": boot_time_str,
            "message": f"System booted at {boot_time_str}"
        }) + "\n"
        
        win32file.WriteFile(pipe_handle, boot_payload.encode('utf-8'))

        # 2. Fetch & Send Current Active Users
        users = list(set([u.name for u in psutil.users()]))
        
        user_payload = json.dumps({
            "timestamp": current_time_str,
            "type": "USER_SESSION_STARTED",
            "active_users": users,
            "message": f"Active user sessions: {', '.join(users)}"
        }) + "\n"
        
        win32file.WriteFile(pipe_handle, user_payload.encode('utf-8'))
    except Exception as e:
        debug_log(f"Error sending initial state over pipe: {e}")

def accept_clients():

    while True:

        pipe = create_named_pipe()

        try:
            try:
                win32pipe.ConnectNamedPipe(pipe, None)

            except win32api.error as e:

                # Client connected before ConnectNamedPipe()
                if e.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise

        
            with clients_lock:
                clients.append(pipe)
            # --- NEW: Send the boot/user data immediately to the new client ---
            send_initial_state(pipe)
    
        except Exception as e:

            try:
                win32file.CloseHandle(pipe)
            except:
                pass

def broadcast_events():
    while True:
        payload = event_queue.get()

        data = (json.dumps(payload) + "\n").encode("utf-8")

        dead = []


        with clients_lock:
           

            for pipe in clients:
                try:
                    win32file.WriteFile(pipe, data)

                except Exception as e:
                    dead.append(pipe)

            for pipe in dead:
                clients.remove(pipe)
                win32file.CloseHandle(pipe)

        event_queue.task_done()

def start_ipc_server():
    threading.Thread(
        target=accept_clients,
        name="Pipe-Accept",
        daemon=True
    ).start()

    threading.Thread(
        target=broadcast_events,
        name="Pipe-Broadcast",
        daemon=True
    ).start()
    
    