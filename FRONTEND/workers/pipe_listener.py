import json, time
import win32file
import pywintypes

from PyQt6.QtCore import QThread, pyqtSignal

class PipeListener(QThread):
    message_received = pyqtSignal(str)
    connection_status = pyqtSignal(bool)
    software_list_received = pyqtSignal(list)

    def __init__(self, pipe_name):
        super().__init__()
        self.pipe_name = pipe_name

    def run(self):
        while True:
            try:
                handle = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ, 
                    0, 
                    None, 
                    win32file.OPEN_EXISTING, 
                    0, 
                    None
                )
                self.connection_status.emit(True)
                
                buffer = ""
                while True:
                    resp = win32file.ReadFile(handle, 4096)
                    if resp[0] == 0:
                        chunk = resp[1].decode('utf-8')
                        buffer += chunk
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            if line.strip():
                                try:
                                    payload = json.loads(line)
                                    if payload.get("type") == "SOFTWARE_LIST":
                                        software_data = payload.get("software_list", [])
                                        self.software_list_received.emit(software_data)
                                    else:
                                        self.message_received.emit(line)
                                except json.JSONDecodeError:
                                    self.message_received.emit(line)
                                    
            except Exception:
                self.connection_status.emit(False)
                time.sleep(3)

def send_backend_command(action,pid=None):
        """
        Opens the command pipe, sends a JSON command, and closes the pipe.
        """        
        pipe_name = r'\\.\pipe\EDR_Commands'
        payload = {
        "action": action,
        "pid": pid
        }
        payload_str = json.dumps(payload)
        
        try:
            handle = win32file.CreateFile(
                pipe_name, win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None
            )
            win32file.WriteFile(handle, payload_str.encode('utf-8'))
            win32file.CloseHandle(handle)
            
            print(f"[GUI] Sent command to backend: {action} PID : {pid}")
            
        except pywintypes.error as e:
            print(f"[GUI] Failed to send command. Is backend listening? Error: {e}")

 