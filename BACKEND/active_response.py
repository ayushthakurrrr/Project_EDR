import os
import shutil
import psutil
import subprocess
import logging

logger = logging.getLogger("EDR.ActiveResponse")

# Safe Quarantine Directory
QUARANTINE_DIR = os.path.join(os.getenv("PROGRAMDATA", r"C:\ProgramData"), "EdrAgent", "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# =====================================================================
# 1. MANUAL PROCESS CONTROL FUNCTIONS (Used by GUI Buttons)
# =====================================================================
def kill_process(pid):
    try:
        proc = psutil.Process(int(pid))
        proc_name = proc.name()
        proc.kill()
        return {"success": True, "pid": pid, "result": f"KILLED {proc_name}", "state": "KILLED"}
    except Exception as e:
        return {"success": False, "pid": pid, "error": str(e)}

def stop_process(pid):
    try:
        proc = psutil.Process(int(pid))
        proc.terminate()
        return {"success": True, "pid": pid, "result": "STOPPED", "state": "STOPPED"}
    except Exception as e:
        return {"success": False, "pid": pid, "error": str(e)}

def restart_process(pid):
    try:
        proc = psutil.Process(int(pid))
        exe = proc.exe()
        proc.kill()
        proc.wait(timeout=2)
        new_proc = psutil.Popen(exe)
        return {"success": True, "old_pid": pid, "new_pid": new_proc.pid, "result": "RESTARTED", "state": "RUNNING"}
    except Exception as e:
        return {"success": False, "pid": pid, "error": str(e)}

# =====================================================================
# 2. AUTO-PILOT CONTAINMENT DISPATCHER
# =====================================================================
def execute_automated_response(payload, auto_pilot_enabled):
    """
    If Auto-Pilot is OFF, does nothing.
    If Auto-Pilot is ON, triggers instant remediation on CRITICAL threats.
    """
    if not auto_pilot_enabled:
        return payload  # Just return the payload unmodified (Manual Mode)

    severity = payload.get("severity", "Low")
    event_type = payload.get("type", "")
    pid = payload.get("pid")
    file_path = payload.get("path")

    # A. AUTOMATED PROCESS KILL
    if severity == "CRITICAL" and pid and str(pid).isdigit():
        res = kill_process(int(pid))
        if res["success"]:
            # ---> FIX: Tell the GUI exactly what happened! <---
            payload["response_action"] = f"AUTO-KILLED PID {pid}"
            payload["status"] = "AUTO-KILLED"
            payload["message"] = payload.get("message", "") + " [🛑 AUTO-KILLED BY EDR]"
            logger.warning(f"AUTO-KILLED PID {pid}")

    # B. AUTOMATED FILE QUARANTINE
    if event_type == "DOWNLOAD_DETECTED" and severity in ["CRITICAL", "HIGH"]:
        if file_path and os.path.exists(file_path):
            try:
                file_name = os.path.basename(file_path)
                vault_path = os.path.join(QUARANTINE_DIR, f"{file_name}.locked")
                shutil.move(file_path, vault_path)
                # ---> FIX: Tell the GUI the file was quarantined! <---
                payload["response_action"] = f"AUTO-QUARANTINED TO {vault_path}"
                payload["status"] = "QUARANTINED"
                payload["message"] = payload.get("message", "") + " [🛑 AUTO-QUARANTINED BY EDR]"
            except Exception as e:
                pass

    return payload