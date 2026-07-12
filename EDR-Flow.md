**1) Main Components of our Project:**

1. Background Service

   1. What it is? The core engine running invisibly as a SYSTEM process. It constantly monitors the operating system to collect running processes, tracks new file downloads, and securely sends this telemetry data to the GUI.
2. Dashboard(GUI)

   1. What it is? The visual interface for the security analyst. It receives data from the Background Service and displays it in an easy-to-read manner.
3. System Tray

   1. What it is? A lightweight process that sits in the Windows taskbar. It shows the status of EDR weather its active or not, and gives the user an easy way to open the dashboard without searching for it.





**2) What our Installer does:**

**End result:**



1\) Creates folders to place executable files, icons, and log files in Program Files and ProgramData.

&#x09;a) Why? We create the EDR Agent folder in Program Files to securely store the executable binaries that run our agent. We create a separate folder in ProgramData to store our log files, ensuring the GUI can read them without triggering "Access Denied" permissions errors.



2\) Creates Start Menu shortcuts to easily open our dashboard via the Windows search bar.



3\) Adds a Registry entry in the HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key.

&#x09;a) Why? So the EDR system tray icon automatically launches every time the system boots up or reboots.



4\) Creates and configures the EDR Background Service.

&#x09;a) What this does: It installs the core engine into the Windows Service Control Manager, sets it to start automatically on boot, and launches it immediately after installation finishes.



5\) Ensures the app shows up under "Add or Remove Programs" in the Control Panel so it can be uninstalled.

&#x09;a) How? The installer automatically adds the application's details to the Windows Uninstall Registry key.



6\) Configures a clean uninstallation process. When uninstalled, it safely tears down the environment: it stops and deletes the background service, terminates running GUI processes, wipes the folders created during installation, and cleans up all related Registry keys.



7\) Finally, after installation, the EDR icon becomes immediately visible in the System Tray.



**What We Learned:**

1\) Learned about software packagers like Inno Setup and how they automate the step-by-step deployment pipeline for an application.

2\) Windows File System Architecture: Gained a deep understanding of the Windows file system, including exactly which directories are meant for static binaries (Program Files) versus dynamic application data (ProgramData).

3\) The Windows Registry: Learned how the Registry acts as the central nervous system for the OS. It controls everything from background startup persistence to application uninstallation paths.





**3) Windows Named Pipes:**

**End result:** Establishes secure communication between the Background Service and the Dashboard (GUI).



&#x20;     	a) Why? Because our background service fetches system telemetry, we need an efficient way to send that data to the UI for display. A Named Pipe creates a fast virtual tunnel between the service and the GUI. Crucially, because our service runs with high-level SYSTEM privileges and the GUI runs as a standard user, Named Pipes securely bridge this privilege gap without requiring us to open vulnerable network ports (like TCP/UDP) on the machine.



&#x09;b) How? We created a pipe server within the background service that actively listens for a connection. When a user opens the dashboard, the pipe client connects, and the server begins pushing data through the tunnel for the UI to read. This tunnel stays active as long as the dashboard is open. If the user closes the dashboard, the client disconnects, and the server gracefully returns to a waiting state, ensuring it doesn't waste resources trying to write data to a closed connection.



**What We Learned:**

1. Different ways of how two processes communicate with each other(Inter Process Communication)
2. About Windows Named Pipe





**4) Telemetry Fetching (Processes, Network \& Software):**

**End Result:** Continuous, real-time visibility into the exact state of the endpoint machine—what is running, what is communicating over the internet, and what is permanently installed—fed directly to the dashboard.



**What it is:** Telemetry fetching is the core "sensor" of the EDR. It is the active surveillance mechanism that constantly interrogates the operating system to gather security-relevant data points. Without this telemetry, the EDR would have nothing to analyze or display to the security analyst.



**How:** We built a multi-faceted scanning engine that uses the best tool for each specific job:



Live Processes: We utilize the WMI (Windows Management Instrumentation) library. This allows us to hook deeply into the Windows OS to capture a highly accurate, live snapshot of all running processes, extracting crucial context like parent-child execution chains and PIDs.



Network Connections: We use the psutil library to monitor active network sockets. This maps running processes to their remote IP addresses and ports, allowing us to detect unauthorized or suspicious outbound data exfiltration.



Software Inventory: Instead of relying on files on the disk, we directly query the Windows Registry (specifically the Uninstall hives for both 64-bit and 32-bit architectures) to track all explicitly installed software, giving us an unalterable list of applications on the system.



**What We Learned:**



**Tool Specialization:** We learned that no single Python library does everything perfectly. WMI is incredibly powerful for deep, Windows-specific process structures, while psutil provides a much faster and cleaner way to parse live network socket data.



**Privilege Execution:** Gathering this level of system telemetry reinforced the concept of Least Privilege. To successfully see all network connections and system-level processes without throwing "Access Denied" errors, the fetching engine must run as a high-privileged background service (NT AUTHORITY\\SYSTEM), rather than as a standard user application.



**Resource Management:** Polling the operating system continuously can spike CPU usage. We learned how to manage these loops efficiently so the EDR sensor remains stealthy and lightweight on the host machine.





**5) Rotating Log Files:**



**What it is**: Log files are the official, time-stamped text records that track all significant events occurring on the endpoint machine.



**Why:** Log files are the foundation of digital forensics. If a system is compromised, security analysts rely on these historical records to trace the attacker's footsteps, determine exactly when a breach occurred, and identify what actions were taken. Without logs, incident response is essentially blind.



**How:** We implemented Python’s built-in logging module to write structured event data to the disk. To prevent these files from consuming all available storage, we built a log rotation mechanism. A new file is generated daily, or whenever a file exceeds a specific size threshold. Once 7 uncompressed files accumulate, the older ones are automatically zipped into an archive. We retain a maximum of 30 days of archived logs before the oldest ones are safely deleted.



**What We Learned:**

1. The critical importance of writing structured logs (like JSON) so they can be easily parsed, filtered, and searched by the GUI later.
2. Storage management in cybersecurity: log files can fill a hard drive rapidly during a system event, making automated rotation and .zip archiving essential to keep the EDR agent lightweight and stable.





**6) Download \& Install Detection:**

**End Result:** Every new file downloaded and every new software installed on the system instantly generates an alert entry in the EDR log file.



**Why:** Malware almost always enters a system through a user downloading a payload or a script secretly installing a malicious application. By tracking these specific actions, analysts can quickly identify the exact file that caused a breach and trace the root cause of the infection.



**How:** We use a dual-monitoring approach. First, we use Python's watchdog library to actively listen to the Windows Downloads directory for file creation events. Second, we monitor the Windows Registry (specifically the Uninstall key) to detect when a new software package registers itself with the operating system. If either system detects a new entry, an alert is formatted and added to the log file.



**What We Learned:**

1. Learned how to interface directly with the OS via Python (using watchdog) to track real-time directory changes asynchronously, without freezing the main application or consuming too much CPU.
2. Discovered that software installations leave permanent footprints in the Windows Registry, making it a much more reliable place to check for new applications rather than just scanning the Program Files directory.


