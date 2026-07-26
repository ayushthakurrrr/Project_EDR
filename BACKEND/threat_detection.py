import urllib.request
import threading
import time

# In-memory threat indicators (Starts with standard test hashes)
GLOBAL_BAD_HASHES = {
    # Standard EICAR test virus hash
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}

GLOBAL_BAD_IPS = {
    # Test IPs
    "185.220.101.7",
    "45.33.32.156"
}

# Feeds
HASH_FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
IP_FEED_URL = "https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt"


def update_threat_intelligence_feeds():
    """
    Background worker that downloads live malware hashes and C2 IPs
    once every 24 hours.
    """
    global GLOBAL_BAD_HASHES, GLOBAL_BAD_IPS
    headers = {'User-Agent': 'Mozilla/5.0 (EDR-Agent-ThreatIntel)'}

    while True:
        try:
            # 1. Fetch recent 48-hr malware hashes from MalwareBazaar
            req = urllib.request.Request(HASH_FEED_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                lines = resp.read().decode('utf-8', errors='ignore').splitlines()
                new_hashes = set()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        new_hashes.add(line.lower())
                
                if new_hashes:
                    GLOBAL_BAD_HASHES.update(new_hashes)

            # 2. Fetch malicious C2 IPs from ThreatFox
            req = urllib.request.Request(IP_FEED_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                lines = resp.read().decode('utf-8', errors='ignore').splitlines()
                new_ips = set()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ip = line.split(":")[0].strip()
                        new_ips.add(ip)
                
                if new_ips:
                    GLOBAL_BAD_IPS.update(new_ips)

        except Exception as e:
            # Silently fallback if offline or network fails
            pass

        # Sleep for 24 hours (86,400 seconds)
        time.sleep(86400)


def start_threat_intel_updater():
    """Launches the background downloader thread."""
    threading.Thread(target=update_threat_intelligence_feeds, name="ThreatIntel-Updater", daemon=True).start()


def evaluate_threat_locally(payload):
    """
    Evaluates raw telemetry events against behavioral rules and blocklists.
    Modifies severity and message if a threat is detected.
    """
    event_type = payload.get("type", "")
    
    if "severity" not in payload:
        payload["severity"] = "Low"

    # 1. DOWNLOAD CHECKS
    if event_type == "DOWNLOAD_DETECTED":
        file_hash = payload.get("sha256", "").lower()
        file_name = payload.get("file_name", "").lower()

        # FIX: Only check the hash if it is a valid 64-character SHA256, 
        # and only if the file is an executable type (ignores .jpg, .png, etc.)
        if len(file_hash) == 64 and file_name.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs")):
            if file_hash in GLOBAL_BAD_HASHES:
                payload["severity"] = "CRITICAL"
                payload["message"] = f"🚨 VIRUS DETECTED! Downloaded file hash matched malware: {file_name}"
                return payload
        
        if file_hash in GLOBAL_BAD_HASHES:
            payload["severity"] = "CRITICAL"
            payload["message"] = f"🚨 VIRUS DETECTED! Downloaded file hash matched malware: {file_name}"
            return payload
            
        if file_name.endswith((".pdf.exe", ".doc.exe", ".png.bat", ".jpg.scr")):
            payload["severity"] = "HIGH"
            payload["message"] = f"🚨 SUSPICIOUS FILE! Double extension detected: {file_name}"
            return payload

    # 2. PROCESS CREATION CHECKS
    elif event_type == "PROCESS_CREATION":
        proc_name = payload.get("process_name", "").lower()
        parent_name = payload.get("parent_name", "").lower()
        cmd_line = payload.get("command_line", "").lower()
        path = payload.get("path", "").lower()
        proc_hash = payload.get("sha256", "").lower()

        if proc_hash in GLOBAL_BAD_HASHES:
            payload["severity"] = "CRITICAL"
            payload["message"] = f"🚨 MALWARE EXECUTED! Process matched known bad hash: {proc_name}"
            return payload

        # Parent-Child Anomaly: Office app opening command prompt/script shell
        if parent_name in ("winword.exe", "excel.exe", "powerpnt.exe"):
            if proc_name in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
                payload["severity"] = "CRITICAL"
                payload["message"] = f"🚨 EXPLOIT ALERT! Office ({parent_name}) spawned shell ({proc_name})!"
                return payload

        # Suspicious PowerShell execution flags
        if proc_name == "powershell.exe":
            if any(kw in cmd_line for kw in ("-enc", "hidden", "downloadstring", "bypass", "iwr")):
                payload["severity"] = "HIGH"
                payload["message"] = f"🚨 SUSPICIOUS SCRIPT! PowerShell executed with hidden/download flags!"
                return payload

        # Execution out of temporary folders
        if "\\appdata\\local\\temp\\" in path or "\\windows\\temp\\" in path:
            payload["severity"] = "MEDIUM"
            payload["message"] = f"⚠️ ANOMALY: Process executing from Temp folder: {proc_name}"
            return payload

    # 3. NETWORK CONNECTION CHECKS
    elif event_type == "NETWORK_CONNECTION":
        proc_name = payload.get("process_name", "").lower()
        remote_ip = payload.get("remote_ip", "")
        remote_port = payload.get("remote_port", 0)

        if remote_ip in GLOBAL_BAD_IPS:
            payload["severity"] = "CRITICAL"
            payload["message"] = f"🚨 C2 ALERT! {proc_name} connected to known malicious IP: {remote_ip}"
            return payload

        if remote_port in (4444, 1337, 8888, 6667):
            payload["severity"] = "HIGH"
            payload["message"] = f"🚨 SUSPICIOUS PORT! {proc_name} connected to hacker port: {remote_port}"
            return payload

        if proc_name in ("calc.exe", "notepad.exe", "mspaint.exe", "wordpad.exe"):
            payload["severity"] = "CRITICAL"
            payload["message"] = f"🚨 ANOMALY! Offline system tool ({proc_name}) connected to the internet!"
            return payload

    return payload