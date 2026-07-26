# 🛡️ SimpleEDR - Endpoint Detection & Response System

**SimpleEDR** is an event-driven, lightweight Endpoint Detection & Response agent designed for Windows. Built natively in Python, it runs as a Session 0 background service (`NT AUTHORITY\SYSTEM`), captures real-time OS telemetry, evaluates behavioral threats using Open-Source Threat Intelligence (OSINT), and streams live JSON alerts to a PyQt6 desktop dashboard over secure Windows Named Pipes.

---

## 🏗️ Architecture & Component Overview

```
 ┌────────────────────────────────────────────────----------------──────────────────────────────┐
 │                                   SESSION 0: SYSTEM DAEMON                                   │
 │                                                                                              │
 │  ┌───────────────────────┐   ┌────────────────────────┐   ┌───────────────────────────────┐  │
 │  │ WMI Process Monitor   │   │ Network Socket Sensor  │   │ Registry Persistence Watcher  │  │
 │  └───────────┬───────────┘   └───────────┬────────────┘   └───────────────┬───────────────┘  │
 │              │                           │                                │                  │
 │              └───────────────────┐       │       ┌────────────────────────┘                  │
 │                                  ▼       ▼       ▼                                           │
 │                            ┌────────────────────────────┐                                    │
 │                            │ Async Download Watcher     │                                    │
 │                            │ (Watchdog + MOTWADS Stream)│                                    │
 │                            └─────────────┬──────────────┘                                    │
 │                                          │                                                   │
 │                                          ▼                                                   │
 │                            ┌────────────────────────────┐                                    │
 │                            │ threat_detection.py        │ ◄─── Daily Threat Intel Feeds      │
 │                            │ (Rules, Hashes & C2 IPs)   │      (MalwareBazaar / ThreatFox)  │
 │                            └─────────────┬──────────────┘                                    │
 └──────────────────────────────────────────┼───────────────────────────────────────────────────┘
                                            │  IPC: Windows Named Pipe
                                            │  (\\.\pipe\SimpleEDRPipe1)
                                            ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                 USER SESSION: FRONTEND GUI                                   │
 │                                                                                              │
 │  ┌────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ PyQt6 Dashboard (Single-Instance Mutex Enforcement)                                   │  │
 │  │ ├── Live Stream (Deduplicated Event Ingestion & High/Med/Low Severity Colors)           │  │
 │  │ ├── Installed Softwares Tab (On-Demand Registry Auditing)                              │  │
 │  │ └── Forensic Logs (Searchable Interactive Terminal & Daily Rotated Archives)           │  │
 │  └────────────────────────────────────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘

```

### Module Breakdown

* **`BACKEND/backend_daemon.py`**: The core Windows Service engine. Handles multi-threaded module initialization, daily 1MB log file rotation, archiving into zip files, and listening for GUI command pipes.
* **`BACKEND/backend_telemetry.py`**: Contains OS telemetry collection sensors:
* **WMI Process Sensor**: Asynchronously captures parent-child lineage and full execution command lines (`CommandLine`).
* **Network Sensor**: Periodically snapshots active TCP sockets via `psutil`, mapping connections to PIDs while filtering out loopbacks and allow-listed applications.
* **Registry Sensor**: Event-driven, zero-CPU persistence watcher (`RegNotifyChangeKeyValue`) monitoring `HKLM\...\Run`.
* **Async Download Watcher**: Recursively monitors `C:\Users`, non-blocking queue processing, deduplicating file writes, and extracting NTFS Mark-of-the-Web (MOTW) `Zone.Identifier` stream data.


* **`threat_detection.py`**: Local evaluation engine. Contains an in-memory LRU SHA256 hash cache, an automated 24-hour background fetcher for live IOC feeds (MalwareBazaar recent malware hashes & ThreatFox C2 IPs), and behavioral heuristic rules.
* **`BACKEND/backend_ipc.py`**: Thread-safe Windows Named Pipe server (`\\.\pipe\SimpleEDRPipe1`) that broadcasts JSON telemetry payloads to GUI clients.
* **`FRONTEND/frontend_gui.py`**: A dark-themed PyQt6 dashboard featuring system tray integration, process details inspection, live filters, and single-instance mutex control.

---

## ⚡ Key Features & Innovations

* **LOLBins & Command-Line Forensics**: Captures full command execution switches (e.g., `powershell.exe -ExecutionPolicy Bypass -EncodedCommand`), revealing obfuscated attacks.
* **Smart SHA256 Caching**: Avoids CPU and Disk I/O bottlenecks by caching binary modification times (`mtime`) alongside computed SHA256 hashes ($O(1)$ lookup speed).
* **Mark-of-the-Web (MOTW) Extraction**: Reads NTFS Alternate Data Streams (`path:Zone.Identifier`) on downloaded files to pinpoint exact referrer and host URLs.
* **Async Non-Blocking Architecture**: Decouples detection triggers from file processing using thread-safe queue workers, preventing file observers from freezing during heavy downloads.
* **Zero-CPU Registry Persistence Guard**: Uses Windows blocking notifications instead of polling loops to detect startup persistence modifications instantly.

---

## 🚀 Building & Bundling Executables

Follow these steps to build standalone binaries and package the installer.

### 1. Environment Setup

Ensure all required dependencies are installed in your local Python environment:

```bash
pip install -r requirements.txt

```

### 2. Bundle Frontend Executable

Build the standalone, GUI dashboard executable:

```bash
pyinstaller --onefile --noconsole --name="EdrAgentGUI" --icon="assets/guard.ico" --add-data "assets/guard.ico;assets" .\FRONTEND\frontend_gui.py

```

### 3. Bundle Backend Service Executable

Build the backend daemon service executable:

```bash
pyinstaller --onefile --name="EdrAgentSERVICE" .\BACKEND\backend_daemon.py

```

### 4. Create the Windows Installer

Compile the Inno Setup script (`inno_script.iss`) using the **Inno Setup Compiler**:

1. Open `inno_script.iss` in Inno Setup Compiler.
2. Click **Build -> Compile**.
3. The standalone installer (`EDRAgentInstaller.exe`) will be generated inside the `dist/` directory.


---

## 📁 Project Directory Layout

```
.
├── assets/
│   └── guard.ico               # System tray & application icon
├── BACKEND/
│   ├── backend_daemon.py       # Main Windows Service daemon entry point
│   ├── backend_telemetry.py    # WMI, Network, Registry & File sensors
│   ├── backend_ipc.py          # Windows Named Pipe server & broadcast logic
│   └── threat_detection.py     # Local rule evaluation & OSINT feed manager
├── FRONTEND/
│   └── frontend_gui.py         # PyQt6 Dashboard & System Tray UI
├── inno_script.iss             # Inno Setup installation script
├── requirements.txt            # Python library dependencies
└── README.md                   # System documentation

```