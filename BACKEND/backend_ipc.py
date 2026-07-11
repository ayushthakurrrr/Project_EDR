import json
import queue
import threading
import win32pipe
import win32file
import win32security
import logging

PIPE_NAME = r'\\.\pipe\SimpleEDRPipe1'

# Shared Global State (Thread-Safe)
event_queue = queue.Queue()
event_counter = 1
counter_lock = threading.Lock()
ALLOW_LIST = set()

def write_to_log_file(payload):
    """Uses Raj's global logger to write telemetry to agent.log"""
    logger = logging.getLogger("EDR")
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
        PIPE_NAME, win32pipe.PIPE_ACCESS_OUTBOUND,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, sa
    )

def start_ipc_server():
    """The master IPC engine. Grabs events from the queue and ships them down the pipe."""
    print("Starting IPC Named Pipe Server...")
    
    while True:
        pipe = create_named_pipe()
        try:
            win32pipe.ConnectNamedPipe(pipe, None)
            print("Client connected to pipe.")
            while True:
                try:
                    payload = event_queue.get(timeout=1)
                    data = (json.dumps(payload) + "\n").encode('utf-8')
                    win32file.WriteFile(pipe, data)
                    event_queue.task_done()
                except queue.Empty:
                    continue
                except Exception:
                    break # Connection to frontend was lost
        except Exception as e:
            print(f"Pipe error: {e}")
        finally:
            win32file.CloseHandle(pipe)