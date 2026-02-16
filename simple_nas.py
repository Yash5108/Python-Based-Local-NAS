import http.server
import socketserver
import os
import posixpath
import urllib.parse
import shutil
import html
import tempfile
import time
import json
import uuid

# try to import cgi but continue if unavailable
try:
    import cgi
    _HAS_CGI = True
except Exception:
    cgi = None
    _HAS_CGI = False

PORT = 8000
DIRECTORY = os.getcwd() # Use the current working directory as the NAS root
MAX_UPLOAD_SIZE = None  # No limit (or set to size in bytes)

# Protect the running script and any filename you want hidden
SCRIPT_NAME = os.path.basename(__file__)
PROTECTED_FILES = {SCRIPT_NAME, "simple_nas.py"}  # add other filenames if needed
PROTECTED_PATHS = { os.path.abspath(os.path.join(DIRECTORY, n)) for n in PROTECTED_FILES }

# Try to set Windows "hidden" attribute for protected files (best-effort)
try:
    if os.name == "nt":
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        for p in PROTECTED_PATHS:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(p), FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass
except Exception:
    pass

# Store pending delete requests with tokens
pending_deletes = {}

class CustomRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler to add upload capabilities."""
    
    def do_POST(self):
        """Handle file uploads and delete requests."""
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/delete':
            # Handle delete request
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                filename = data.get('file', '')
                action = data.get('action', '')
            except:
                self.send_json_response(400, {'error': 'Invalid JSON'})
                return
            
            if action == 'request':
                # User requested to delete a file
                self._handle_delete_request(filename)
            elif action == 'confirm':
                # Server admin confirmed the delete
                token = data.get('token', '')
                self._handle_delete_confirm(filename, token)
            else:
                self.send_json_response(400, {'error': 'Invalid action'})
            return
        
        # Handle regular file upload
        r, info = self.deal_post_data()
        print(r, info, "by: %s" % self.client_address[0])
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def _handle_delete_request(self, filename):
        """Generate a delete token and ask admin for confirmation."""
        safe_name = os.path.basename(filename)

        # Protect files — immediate deny
        if safe_name in PROTECTED_FILES:
            self.send_json_response(403, {'error': 'File is protected'})
            return

        file_path = os.path.join(DIRECTORY, safe_name)
        
        if not os.path.isfile(file_path):
            self.send_json_response(404, {'error': 'File not found'})
            return
        
        # Generate a unique token for this delete request
        token = str(uuid.uuid4())
        client_ip = self.client_address[0]
        
        # Store the request
        pending_deletes[token] = {
            'file': safe_name,
            'path': file_path,
            'ip': client_ip,
            'time': time.time()
        }
        
        # Prompt the server admin
        print("\n" + "="*60)
        print(f"DELETE REQUEST from {client_ip}")
        print(f"File: {safe_name}")
        print(f"Token: {token}")
        print(f"Allow deletion? (yes/no): ", end='', flush=True)
        
        # Read admin response
        try:
            response = input().strip().lower()
            if response == 'yes':
                # Auto-confirm
                self._execute_delete(safe_name, file_path, token)
                self.send_json_response(200, {'status': 'File deleted', 'token': token})
                print(f"✓ File '{safe_name}' deleted by admin approval")
                del pending_deletes[token]
            else:
                self.send_json_response(403, {'error': 'Delete request denied by admin', 'token': token})
                print(f"✗ Delete request denied")
                del pending_deletes[token]
        except KeyboardInterrupt:
            self.send_json_response(500, {'error': 'Server interrupted'})
            print(f"\n✗ Delete request cancelled (server interrupted)")
            del pending_deletes[token]

    def _handle_delete_confirm(self, filename, token):
        """Handle client-side confirmation (if needed)."""
        if token not in pending_deletes:
            self.send_json_response(404, {'error': 'Invalid or expired token'})
            return
        
        req = pending_deletes[token]
        if req['file'] != os.path.basename(filename):
            self.send_json_response(400, {'error': 'File mismatch'})
            return
        
        self._execute_delete(req['file'], req['path'], token)
        self.send_json_response(200, {'status': 'File deleted'})
        del pending_deletes[token]

    def _execute_delete(self, filename, filepath, token):
        """Actually delete the file."""
        try:
            if os.path.isfile(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"Error deleting {filename}: {e}")

    def send_json_response(self, status_code, data):
        """Send a JSON response."""
        response = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        """Handle download requests at /download?file=<name>, otherwise fall back."""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/download':
            qs = urllib.parse.parse_qs(parsed.query)
            if 'file' not in qs or not qs['file']:
                self.send_error(400, "Missing 'file' parameter")
                return
            fname = qs['file'][0]
            # sanitize filename
            safe_name = os.path.basename(fname)

            # Protect files from download
            if safe_name in PROTECTED_FILES:
                self.send_error(404, "File not found")
                return

            file_path = os.path.join(DIRECTORY, safe_name)
            if not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return
            try:
                ctype = self.guess_type(file_path)
                fs = os.path.getsize(file_path)
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(fs))
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    shutil.copyfileobj(f, self.wfile)
            except Exception as e:
                self.send_error(500, f"Error serving file: {e}")
            return
        # default behavior for other GETs
        return super().do_GET()

    def deal_post_data(self):
        """Process the post data for file upload."""
        content_type = self.headers.get('content-type')
        if not content_type:
            return (False, "Content-Type header missing")
        if 'multipart/form-data' not in content_type:
            return (False, "Only multipart/form-data supported")

        # Reject very large uploads early (basic protection)
        try:
            content_length = int(self.headers.get('content-length', 0))
        except (TypeError, ValueError):
            content_length = 0
        if MAX_UPLOAD_SIZE and content_length > MAX_UPLOAD_SIZE:
            return (False, f"Upload too large (>{MAX_UPLOAD_SIZE / (1024*1024):.0f} MB)")

        # If cgi.FieldStorage is available, use it; otherwise use a minimal parser
        if _HAS_CGI:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': content_type},
                keep_blank_values=True
            )
            if 'file_upload' not in form:
                return (False, "No file_upload field in form")

            file_items = form['file_upload']
            if not isinstance(file_items, list):
                file_items = [file_items]

            uploaded_files = []
            for item in file_items:
                if item.filename:
                    fn = os.path.basename(item.filename)

                    # Prevent uploads overwriting protected files
                    if fn in PROTECTED_FILES:
                        return (False, "Cannot overwrite protected file: %s" % fn)

                    dest_path = os.path.join(DIRECTORY, fn)
                    try:
                        with tempfile.NamedTemporaryFile(dir=DIRECTORY, delete=False) as tmpf:
                            shutil.copyfileobj(item.file, tmpf)
                            tmpname = tmpf.name
                        os.replace(tmpname, dest_path)
                        uploaded_files.append(fn)
                    except IOError:
                        try:
                            os.unlink(tmpname)
                        except Exception:
                            pass
                        return (False, "Can't create file: %s" % fn)

            if uploaded_files:
                return (True, "Files uploaded: %s" % ", ".join(uploaded_files))
            else:
                return (False, "No files uploaded")

        # Minimal multipart/form-data parser (fallback when cgi missing)
        # Note: simple implementation for common browser uploads.
        boundary = None
        parts = content_type.split(';')
        for p in parts:
            p = p.strip()
            if p.startswith('boundary='):
                boundary = p.split('=', 1)[1]
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]
                break
        if not boundary:
            return (False, "No boundary in Content-Type")

        try:
            body = self.rfile.read(content_length)
        except Exception as e:
            return (False, f"Failed to read request body: {e}")

        b_boundary = b'--' + boundary.encode('utf-8')
        raw_parts = body.split(b_boundary)
        uploaded_files = []

        for raw in raw_parts:
            if not raw:
                continue
            # strip leading/trailing CRLF and final '--'
            if raw.startswith(b'\r\n'):
                raw = raw[2:]
            if raw.endswith(b'--\r\n') or raw.endswith(b'--'):
                raw = raw.rstrip(b'-\r\n')
            if not raw:
                continue

            try:
                header_blob, part_body = raw.split(b'\r\n\r\n', 1)
            except ValueError:
                continue
            # remove trailing CRLF
            if part_body.endswith(b'\r\n'):
                part_body = part_body[:-2]

            header_lines = header_blob.decode('utf-8', errors='ignore').split('\r\n')
            headers = {}
            for hl in header_lines:
                if ':' in hl:
                    k, v = hl.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            cd = headers.get('content-disposition', '')
            if 'filename=' in cd:
                # parse name and filename
                # Content-Disposition: form-data; name="file_upload"; filename="foo.txt"
                fn = None
                for part in cd.split(';'):
                    part = part.strip()
                    if part.startswith('filename='):
                        val = part.split('=', 1)[1].strip()
                        if val.startswith('"') and val.endswith('"'):
                            val = val[1:-1]
                        fn = os.path.basename(val)
                        break
                if not fn:
                    continue
                dest_path = os.path.join(DIRECTORY, fn)
                try:
                    with tempfile.NamedTemporaryFile(dir=DIRECTORY, delete=False) as tmpf:
                        tmpf.write(part_body)
                        tmpname = tmpf.name
                    os.replace(tmpname, dest_path)
                    uploaded_files.append(fn)
                except Exception:
                    try:
                        os.unlink(tmpname)
                    except Exception:
                        pass
                    return (False, f"Can't create file: {fn}")

        if uploaded_files:
            return (True, "Files uploaded: %s" % ", ".join(uploaded_files))
        else:
            return (False, "No files uploaded")

    def list_directory(self, path):
        """Serve the list of files in the directory with drag-and-drop upload and responsive UI."""
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        
        r = []
        r.append('<!DOCTYPE html>')
        r.append('<html lang="en"><head><meta charset="utf-8">')
        r.append('<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">')
        r.append('<title>Python NAS Server</title>')
        r.append('<link rel="preconnect" href="https://fonts.googleapis.com">')
        r.append('<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">')
        r.append('<style>')
        r.append('''
/* ── Reset & Base ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --surface-hover: #222632;
  --border: #2a2e3b;
  --border-accent: #3b82f6;
  --text: #e4e4e7;
  --text-muted: #9ca3af;
  --primary: #3b82f6;
  --primary-hover: #2563eb;
  --success: #22c55e;
  --success-bg: rgba(34,197,94,0.12);
  --danger: #ef4444;
  --danger-hover: #dc2626;
  --danger-bg: rgba(239,68,68,0.12);
  --radius: 12px;
  --radius-sm: 8px;
  --shadow: 0 4px 24px rgba(0,0,0,0.35);
}

body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: clamp(12px, 4vw, 40px);
}

.container {
  max-width: 900px;
  margin: 0 auto;
}

/* ── Header ── */
.header {
  text-align: center;
  margin-bottom: 32px;
}
.header h1 {
  font-size: clamp(1.4rem, 4vw, 2rem);
  font-weight: 700;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.header p {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin-top: 4px;
}

/* ── Cards ── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: clamp(16px, 3vw, 28px);
  margin-bottom: 24px;
  box-shadow: var(--shadow);
}
.card-title {
  font-size: 1.05rem;
  font-weight: 600;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ── Drop Zone ── */
.drop-zone {
  border: 2px dashed var(--border);
  border-radius: var(--radius);
  padding: clamp(28px, 5vw, 48px) 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.25s, background 0.25s, transform 0.15s;
  position: relative;
}
.drop-zone:hover {
  border-color: var(--primary);
  background: rgba(59,130,246,0.04);
}
.drop-zone.drag-over {
  border-color: var(--primary);
  background: rgba(59,130,246,0.1);
  transform: scale(1.01);
}
.drop-zone-icon {
  font-size: 2.5rem;
  margin-bottom: 12px;
  display: block;
}
.drop-zone-text {
  font-size: 1rem;
  color: var(--text-muted);
  line-height: 1.6;
}
.drop-zone-text strong {
  color: var(--primary);
}
.drop-zone input[type="file"] {
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
}

/* ── Progress ── */
#progressContainer {
  display: none;
  margin-top: 20px;
}
.progress-bar {
  width: 100%;
  height: 28px;
  background: var(--bg);
  border-radius: 14px;
  overflow: hidden;
  border: 1px solid var(--border);
}
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--primary), #8b5cf6);
  width: 0%;
  transition: width 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: 600;
  font-size: 0.8rem;
  border-radius: 14px;
  min-width: 36px;
}
.progress-info {
  margin-top: 10px;
  font-size: 0.85rem;
  color: var(--text-muted);
  display: flex;
  flex-wrap: wrap;
  gap: 8px 20px;
}

/* ── Buttons ── */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 14px;
  font-size: 0.85rem;
  font-weight: 500;
  text-decoration: none;
  border-radius: var(--radius-sm);
  border: none;
  cursor: pointer;
  transition: background 0.2s, transform 0.1s;
  white-space: nowrap;
  min-height: 38px;
  font-family: inherit;
}
.btn:active { transform: scale(0.96); }
.btn-download { background: var(--success-bg); color: var(--success); border: 1px solid rgba(34,197,94,0.2); }
.btn-download:hover { background: rgba(34,197,94,0.2); }
.btn-delete { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
.btn-delete:hover { background: rgba(239,68,68,0.2); }

/* ── File List ── */
.file-list { list-style: none; }
.file-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: var(--radius-sm);
  transition: background 0.15s;
  border-bottom: 1px solid var(--border);
}
.file-item:last-child { border-bottom: none; }
.file-item:hover { background: var(--surface-hover); }
.file-icon { font-size: 1.3rem; flex-shrink: 0; }
.file-info { flex: 1; min-width: 0; }
.file-name {
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.file-name a { color: var(--primary); text-decoration: none; }
.file-name a:hover { text-decoration: underline; }
.file-size { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }
.file-actions { display: flex; gap: 8px; flex-shrink: 0; }

/* ── Toast Notifications ── */
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: none;
}
.toast {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 20px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  font-size: 0.9rem;
  pointer-events: auto;
  animation: toastIn 0.3s ease;
  max-width: 340px;
}
.toast.success { border-left: 4px solid var(--success); }
.toast.error { border-left: 4px solid var(--danger); }
.toast.info { border-left: 4px solid var(--primary); }
@keyframes toastIn {
  from { opacity: 0; transform: translateX(40px); }
  to { opacity: 1; transform: translateX(0); }
}

/* ── Empty State ── */
.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-muted);
}
.empty-state-icon { font-size: 2.5rem; margin-bottom: 12px; display: block; }

/* ── Mobile-first responsive ── */
@media (max-width: 640px) {
  .file-item {
    flex-wrap: wrap;
    padding: 12px;
    gap: 8px;
  }
  .file-info { width: calc(100% - 44px); }
  .file-actions {
    width: 100%;
    justify-content: flex-end;
  }
  .btn { min-height: 44px; padding: 10px 16px; font-size: 0.9rem; }
  .toast-container { top: 10px; right: 10px; left: 10px; }
  .toast { max-width: 100%; }
}
        ''')
        r.append('</style>')
        r.append('</head>')
        r.append('<body>')
        r.append('<div class="container">')

        # Header
        r.append('<div class="header">')
        r.append('<h1>📡 Python NAS Server</h1>')
        r.append('<p>File Manager</p>')
        r.append('</div>')

        # Toast container
        r.append('<div class="toast-container" id="toastContainer"></div>')

        # Upload section with drag-and-drop
        r.append('<div class="card">')
        r.append('<div class="card-title">⬆️ Upload Files</div>')
        r.append('<form id="uploadForm" enctype="multipart/form-data" method="post">')
        r.append('<div class="drop-zone" id="dropZone">')
        r.append('<span class="drop-zone-icon">📂</span>')
        r.append('<div class="drop-zone-text"><strong>Drag &amp; drop files here</strong><br>or click to browse</div>')
        r.append('<input type="file" id="fileInput" name="file_upload" multiple>')
        r.append('</div>')
        r.append('</form>')
        r.append('<div id="progressContainer">')
        r.append('<div class="progress-bar"><div class="progress-fill" id="progressFill">0%</div></div>')
        r.append('<div class="progress-info">')
        r.append('<span id="uploadStatus">Uploading...</span>')
        r.append('<span id="uploadSpeed">Speed: 0 KB/s</span>')
        r.append('<span id="uploadTime">Time: 0s</span>')
        r.append('</div>')
        r.append('</div>')
        r.append('</div>')

        # File listing
        r.append('<div class="card">')
        r.append('<div class="card-title">📁 Files</div>')

        file_count = 0
        r.append('<ul class="file-list">')
        for name in list:
            if name in PROTECTED_FILES:
                continue
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
                r.append('<li class="file-item">')
                r.append('<span class="file-icon">📁</span>')
                r.append('<div class="file-info"><div class="file-name"><a href="%s">%s</a></div><div class="file-size">Folder</div></div>' %
                        (urllib.parse.quote(linkname), html.escape(displayname)))
                r.append('</li>')
                file_count += 1
            else:
                try:
                    fsize = os.path.getsize(fullname)
                    fsize_str = self.format_file_size(fsize)
                except:
                    fsize_str = "?"
                if os.path.islink(fullname):
                    displayname = name + "@"
                dl_url = "/download?file=" + urllib.parse.quote(linkname)
                r.append('<li class="file-item">')
                r.append('<span class="file-icon">📄</span>')
                r.append('<div class="file-info"><div class="file-name">%s</div><div class="file-size">%s</div></div>' % (html.escape(displayname), fsize_str))
                r.append('<div class="file-actions">')
                r.append('<a href="%s" class="btn btn-download">⬇ Download</a>' % dl_url)
                esc_name = html.escape(name).replace("'", "\\'")
                r.append('<button class="btn btn-delete" onclick="deleteFile(\'%s\')">🗑 Delete</button>' % esc_name)
                r.append('</div>')
                r.append('</li>')
                file_count += 1

        r.append('</ul>')

        if file_count == 0:
            r.append('<div class="empty-state"><span class="empty-state-icon">📭</span>No files yet — drop some above!</div>')

        r.append('</div>')  # end files card

        # JavaScript
        r.append('<script>')
        r.append('''
/* ── Toast helper ── */
function showToast(message, type) {
    type = type || 'info';
    var container = document.getElementById('toastContainer');
    var toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function() { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; setTimeout(function() { toast.remove(); }, 300); }, 4000);
}

/* ── Drag & Drop ── */
var dropZone = document.getElementById('dropZone');
var fileInput = document.getElementById('fileInput');

// Prevent default drag on the whole page
['dragenter','dragover','dragleave','drop'].forEach(function(evt) {
    document.addEventListener(evt, function(e) { e.preventDefault(); e.stopPropagation(); });
});

// Visual feedback on the drop zone
['dragenter','dragover'].forEach(function(evt) {
    dropZone.addEventListener(evt, function() { dropZone.classList.add('drag-over'); });
});
['dragleave','drop'].forEach(function(evt) {
    dropZone.addEventListener(evt, function() { dropZone.classList.remove('drag-over'); });
});

// Handle dropped files
dropZone.addEventListener('drop', function(e) {
    var files = e.dataTransfer.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
});

// Handle file input change (click-to-browse)
fileInput.addEventListener('change', function() {
    if (fileInput.files.length > 0) {
        uploadFiles(fileInput.files);
    }
});

// Prevent form default submit (we handle it via JS)
document.getElementById('uploadForm').addEventListener('submit', function(e) {
    e.preventDefault();
    if (fileInput.files.length === 0) {
        showToast('Please select files to upload', 'error');
        return;
    }
    uploadFiles(fileInput.files);
});

/* ── Upload with XHR + progress ── */
function uploadFiles(files) {
    var formData = new FormData();
    var totalSize = 0;
    var names = [];
    for (var i = 0; i < files.length; i++) {
        formData.append('file_upload', files[i]);
        totalSize += files[i].size;
        names.push(files[i].name);
    }
    showToast('Uploading ' + files.length + ' file(s)...', 'info');

    var progressContainer = document.getElementById('progressContainer');
    var progressFill = document.getElementById('progressFill');
    var uploadStatus = document.getElementById('uploadStatus');
    var uploadSpeed = document.getElementById('uploadSpeed');
    var uploadTime = document.getElementById('uploadTime');

    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressFill.textContent = '0%';
    var startTime = Date.now();

    var xhr = new XMLHttpRequest();
    xhr.upload.addEventListener('progress', function(e) {
        if (e.lengthComputable) {
            var percent = (e.loaded / e.total) * 100;
            progressFill.style.width = percent + '%';
            progressFill.textContent = Math.round(percent) + '%';
            var elapsed = (Date.now() - startTime) / 1000;
            var speed = (e.loaded / 1024 / elapsed).toFixed(2);
            uploadStatus.textContent = 'Uploading: ' + e.loaded.toLocaleString() + ' / ' + e.total.toLocaleString() + ' bytes';
            uploadSpeed.textContent = 'Speed: ' + speed + ' KB/s';
            uploadTime.textContent = 'Time: ' + Math.round(elapsed) + 's';
        }
    });
    xhr.addEventListener('load', function() {
        if (xhr.status === 303 || xhr.status === 200) {
            showToast('Upload complete!', 'success');
            uploadStatus.textContent = 'Upload complete! Reloading...';
            setTimeout(function() { window.location.reload(); }, 1200);
        } else {
            showToast('Upload failed!', 'error');
            uploadStatus.textContent = 'Upload failed!';
        }
    });
    xhr.addEventListener('error', function() {
        showToast('Upload error — check connection', 'error');
        uploadStatus.textContent = 'Upload error!';
    });
    xhr.open('POST', '/', true);
    xhr.send(formData);
}

/* ── Delete ── */
function deleteFile(filename) {
    if (!confirm('Delete "' + filename + '"?')) return;

    var progressContainer = document.getElementById('progressContainer');
    var progressFill = document.getElementById('progressFill');
    var uploadStatus = document.getElementById('uploadStatus');

    progressContainer.style.display = 'block';
    uploadStatus.textContent = 'Requesting delete approval from server...';
    progressFill.style.width = '50%';
    progressFill.textContent = '...';

    fetch('/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file: filename, action: 'request'})
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.error) {
            showToast('Delete denied: ' + data.error, 'error');
            progressFill.style.width = '100%';
            progressFill.textContent = '✗';
            setTimeout(function() { progressContainer.style.display = 'none'; }, 3000);
        } else {
            showToast('File deleted!', 'success');
            progressFill.style.width = '100%';
            progressFill.textContent = '✓';
            setTimeout(function() { window.location.reload(); }, 1200);
        }
    })
    .catch(function(err) {
        showToast('Error: ' + err, 'error');
        progressFill.style.width = '100%';
        progressFill.textContent = '✗';
        setTimeout(function() { progressContainer.style.display = 'none'; }, 3000);
    });
}

/* ── Download with progress ── */
document.addEventListener('click', function(e) {
    var btn = e.target.closest('.btn-download');
    if (!btn) return;
    e.preventDefault();
    var url = btn.href;
    var filename = new URLSearchParams(new URL(url, window.location).search).get('file');

    var progressContainer = document.getElementById('progressContainer');
    var progressFill = document.getElementById('progressFill');
    var uploadStatus = document.getElementById('uploadStatus');
    var uploadSpeed = document.getElementById('uploadSpeed');
    var uploadTime = document.getElementById('uploadTime');

    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    var startTime = Date.now();

    fetch(url)
        .then(function(response) {
            var total = parseInt(response.headers.get('content-length'), 10);
            var reader = response.body.getReader();
            var loaded = 0;
            var chunks = [];

            function pump() {
                return reader.read().then(function(result) {
                    if (result.done) {
                        var blob = new Blob(chunks);
                        var dlUrl = window.URL.createObjectURL(blob);
                        var a = document.createElement('a');
                        a.href = dlUrl; a.download = filename;
                        document.body.appendChild(a); a.click();
                        window.URL.revokeObjectURL(dlUrl);
                        document.body.removeChild(a);
                        showToast('Download complete!', 'success');
                        uploadStatus.textContent = 'Download complete!';
                        setTimeout(function() { progressContainer.style.display = 'none'; }, 2000);
                        return;
                    }
                    chunks.push(result.value);
                    loaded += result.value.length;
                    var percent = (loaded / total) * 100;
                    progressFill.style.width = percent + '%';
                    progressFill.textContent = Math.round(percent) + '%';
                    var elapsed = (Date.now() - startTime) / 1000;
                    var speed = (loaded / 1024 / elapsed).toFixed(2);
                    uploadStatus.textContent = 'Downloading: ' + loaded.toLocaleString() + ' / ' + total.toLocaleString() + ' bytes';
                    uploadSpeed.textContent = 'Speed: ' + speed + ' KB/s';
                    uploadTime.textContent = 'Time: ' + Math.round(elapsed) + 's';
                    return pump();
                });
            }
            return pump();
        })
        .catch(function(err) {
            showToast('Download failed!', 'error');
            uploadStatus.textContent = 'Download failed!';
            console.error(err);
        });
});
        ''')
        r.append('</script>')

        r.append('</div>')  # end container
        r.append('</body></html>')

        encoded = '\n'.join(r).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=%s" % 'utf-8')
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None

    def format_file_size(self, size):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

# --- Server Startup ---
if __name__ == '__main__':
    handler = CustomRequestHandler
    # ensure serving directory
    os.chdir(DIRECTORY)
    import socket

    class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True  # let worker threads exit on shutdown

    bind_addr = "0.0.0.0"  # listen on all interfaces

    # determine a likely LAN IP for printing (doesn't send traffic)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        local_ip = "127.0.0.1"

    try:
        with ThreadingTCPServer((bind_addr, PORT), handler) as httpd:
            print(f"Serving at {bind_addr}:{PORT} (dir: {DIRECTORY})")
            print(f"Accessible locally: http://localhost:{PORT}")
            print(f"Accessible on LAN:   http://{local_ip}:{PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")


