# Secure Python NAS Server

A production-ready, secure Network Attached Storage (NAS) server built with Python. It provides HTTPS, authentication, CSRF protection, rate limiting, and a modern web interface for uploads and downloads.

## Features

- HTTPS/TLS encryption (TLS 1.2+)
- Password authentication (SHA-256 hash)
- CSRF protection for uploads and deletes
- Rate limiting for login attempts
- Secure session cookies (HttpOnly, Secure, SameSite)
- File uploads with progress UI
- File downloads with progress UI
- Optional delete confirmation on server console
- Live reload via Server-Sent Events (SSE)
- Hidden/protected files support

## Requirements

- Python 3.7 or higher
- PyOpenSSL (optional, for automatic certificate generation)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Yash5108/Python-Based-Local-NAS.git
cd Python-Based-Local-NAS
```

### 2. Set a strong password

Edit `simple_nas.py` and set:

```python
NAS_PASSWORD = "YourStrongPassword123!"
```

### 3. Install PyOpenSSL (optional)

```bash
pip install pyopenssl
```

### 4. Run the server

```bash
py simple_nas.py
```

### 5. Open the UI

- Local: https://localhost:8443
- LAN: https://YOUR_IP:8443

You will see a browser warning for the self-signed certificate. Click Advanced and proceed.

## File Storage

All user files are stored in the `nas container` folder. The parent directory and hidden files are not accessible from the web UI.

## Configuration

Edit these values in `simple_nas.py`:

```python
PORT = 8443                           # HTTPS port
USE_HTTPS = True                      # Enable/disable HTTPS
MAX_UPLOAD_SIZE = 5120 * 1024 * 1024  # 5 GB upload limit
NAS_PASSWORD = ""                     # Set your password here
DIRECTORY = "nas container"           # Folder for shared files
```

## Documentation

- [SETUP_GUIDE.md](SETUP_GUIDE.md)
- [SECURITY.md](SECURITY.md)
- [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md)
- [GITHUB_UPLOAD_LIST.md](GITHUB_UPLOAD_LIST.md)

## Contacts

- Gmail: yash5108@gmail.com
- LinkedIn: https://www.linkedin.com/in/yash-jain-540a9a271/
- GitHub: https://github.com/Yash5108

## License

Add a LICENSE file if you want to publish this publicly.
