# Python-Based Local NAS Server

A lightweight, secure, and highly responsive local Network Attached Storage (NAS) server built entirely in pure Python. It requires zero third-party dependencies, running smoothly on Python's standard library. 

This script transforms any folder on your computer into a local cloud, accessible from any device (phone, laptop, tablet) on the same Wi-Fi network.

---

## ✨ Features
* **Zero Dependencies:** Pure Python, no `pip install` required.
* **Modern Web UI:** Responsive, mobile-friendly interface with drag-and-drop uploads.
* **Highly Concurrent & Non-Blocking:**
  * Uses in-thread SSL wrapping during request setup instead of locking the main socket listener thread.
  * Stalled client handshakes or partial requests never freeze the server for other clients.
* **Memory-Safe File Streaming:**
  * Employs a streaming multipart parser that reads uploads in 64KB chunks and streams them directly to disk.
  * Upload multi-gigabyte files without memory spikes or Out-Of-Memory (OOM) crashes.
* **Secure by Default:** 
  * HTTPS support (auto-generates self-signed certificates).
  * Optional password authentication (with SHA-256 hashing).
  * Rate limiting and brute-force lockout.
  * CSRF protection and secure session management.
  * Thread-safe session, login, and deletion states protected by locks.
* **Real-time Live Reload:** 
  * UI automatically updates across all devices when files are added or deleted using Server-Sent Events (SSE).
  * SSE client connections utilize heartbeats to prune terminated connections and prevent thread/resource leaks.
* **High Performance Metadata:** 
  * Fast directory scanning using `os.scandir` to minimize I/O calls.
  * Adaptive background file watcher polling (every 1s when active, slowing down to 5s when idle to save CPU).
* **Robust File Management:** Supports large file uploads, downloads, and file unlinking. Includes visual thumbnail previews for image files.

---

## 🚀 Getting Started

### 1. Requirements
* Python 3.7 or newer installed on your system.

### 2. Running the Server
Open a terminal in the folder containing `nas.py` and run:

```bash
python nas.py
```

The script will automatically:
1. Create a `nas container/` directory to store your files safely.
2. Generate an SSL certificate (if HTTPS is enabled).
3. Start the server on `0.0.0.0:8443` (or `8000` for HTTP).

### 3. Accessing the NAS
Look at the terminal output to find your LAN IP. It will look something like this:
```
🌐 Access URLs:
   Local:  https://localhost:8443
   LAN:    https://192.168.10.40:8443
```
Type the LAN URL into a browser on any device connected to the same Wi-Fi network. 

**Note on Security Warnings:** Because it uses a self-signed certificate, your browser will warn you that the connection is "Not Private". This is normal for local networks. Click **Advanced -> Proceed to [IP] (unsafe)**.

---

## ⚙️ Configuration
You can customize the server by editing these variables at the top of `nas.py`:

* `USE_HTTPS` (bool): Enable or disable HTTPS.
* `NAS_PASSWORD` (str): Set a password to require login. (Empty by default).
* `PORT` (int): Change the listening port (default 8443 for HTTPS, 8000 for HTTP).
* `MAX_UPLOAD_SIZE`: Maximum allowed upload file size (default is 5 GB).
* `DIRECTORY`: Where uploaded files are saved (default is `"nas container"`).

---

## 🛠️ Troubleshooting (Can't Connect?)
If you cannot access the NAS from your phone or another computer:
1. Ensure both devices are on the exact same Wi-Fi network.
2. Ensure your Wi-Fi network profile on Windows is set to **Private**, not Public.
3. **Windows Firewall:** By default, Windows blocks incoming connections. You must allow Python through the firewall. Open PowerShell as Administrator and run:
   ```powershell
   New-NetFirewallRule -DisplayName "Python NAS Server" -Direction Inbound -LocalPort 8443,8000 -Protocol TCP -Action Allow
   ```

---

## 📬 Contact
Author: Yash Jain
* [Email](mailto:yash5108@gmail.com)
* [LinkedIn](https://www.linkedin.com/in/yash-jain-540a9a271/)
* [GitHub](https://github.com/Yash5108)
