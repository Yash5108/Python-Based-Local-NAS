# Python NAS Server

A tiny file-server / simple NAS written with Python's built-in http.server. It supports drag-and-drop uploads, downloads with progress, delete requests (admin-confirmed), and automatic browser live-reload when files change.

## Features

- Browse files and folders in the serving directory
- Drag & drop or click-to-browse file uploads (multipart/form-data)
- Download files with progress
- Delete requests that require server admin confirmation
- Live-reload in connected browsers via Server-Sent Events (SSE)

## Requirements

- Python 3.8+
- No external packages required

## Quick Start

Open PowerShell, change to the project directory and run:

```powershell
cd "d:\YASH\local nas"
python simple_nas.py
```

By default the server listens on port 8000. You can open the UI at:

- http://localhost:8000

The server prints the LAN address (if available) when it starts.

## Configuration

You can change these variables at the top of `simple_nas.py`:

- `PORT` — TCP port the server listens on (default: `8000`)
- `DIRECTORY` — root directory served (default: current working directory)
- `MAX_UPLOAD_SIZE` — optional maximum upload size in bytes (default: `None` = unlimited)
- `PROTECTED_FILES` — set of filenames that cannot be overwritten, downloaded, or deleted

## Live-reload behavior

The server exposes an SSE endpoint at `/events`. Browsers connect automatically and will reload when the server detects changes in the serving directory. The server uses a lightweight polling watcher (checks every 1s) that notifies connected clients.

If you prefer a different strategy (inotify, Watchdog, or polling interval change), edit the watcher implementation in `simple_nas.py`.

## Security notes

- This project is intended for local/trusted networks and simple personal use. It does not implement authentication.
- Keep `PROTECTED_FILES` populated with any sensitive filenames (for example `simple_nas.py`).
- Consider running behind a reverse proxy with TLS for exposure to untrusted networks.

## Troubleshooting

- If browsers don't auto-reload, ensure your browser allows SSE and that no proxy blocks `text/event-stream` responses.
- If uploads fail, check `MAX_UPLOAD_SIZE` and file permissions in the serving directory.

## Files

- `simple_nas.py` — main server script

---
Created for quick local file sharing with live-reload.
