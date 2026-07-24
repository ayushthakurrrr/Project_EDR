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

def accept_clients():

    while True:

        pipe = create_named_pipe()

        write_to_log_file({
    "component": "PIPE",
    "event": "WAITING_FOR_CLIENT"
})

        try:
            try:
                win32pipe.ConnectNamedPipe(pipe, None)

            except win32api.error as e:

                # Client connected before ConnectNamedPipe()
                if e.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise

        
            with clients_lock:
                clients.append(pipe)
                write_to_log_file({
    "component": "PIPE",
    "event": "CLIENT_CONNECTED",
    "total_clients": len(clients)
})

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
                    write_to_log_file({
    "component": "PIPE",
    "event": "BROADCAST",
    "clients": len(clients)
})

                except Exception as e:
                    dead.append(pipe)
                    write_to_log_file({
        "component": "PIPE",
        "event": "WRITE_FAILED",
        "error": str(e),
        "client": str(pipe)
    })

            for pipe in dead:
                clients.remove(pipe)
                win32file.CloseHandle(pipe)

        event_queue.task_done()

def start_ipc_server():
    write_to_log_file({
        "component": "PIPE",
        "event": "IPC server started"
    })
   

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
    write_to_log_file({
        "component": "PIPE",
        "event": "IPC threads started"
    })
    