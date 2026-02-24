import http.server
import socketserver
import ssl
# import cgi   <-- removed, use fallback parser if cgi missing
import os
import posixpath
import urllib.parse
import shutil
import html
import tempfile
import time
import json
import uuid
import threading
import hashlib
import hmac
import secrets
import sys
from datetime import datetime
from collections import defaultdict

# Fix Windows console encoding for emoji support
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Safe print function for Windows console
def safe_print(text):
    """Print text, handling Unicode encoding errors on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Remove emoji and special characters if encoding fails
        import re
        clean_text = re.sub(r'[^\x00-\x7F]+', '', text)
        print(clean_text)

# try to import cgi but continue if unavailable
try:
    import cgi
    _HAS_CGI = True
except Exception:
    cgi = None
    _HAS_CGI = False

PORT = 8443  # HTTPS port (use 443 for production)
# Base directory (project root)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# NAS Container - all shared files stored here (keeps parent directory protected)
DIRECTORY = os.path.join(BASE_DIR, "nas container")
MAX_UPLOAD_SIZE = 5120 * 1024 * 1024  # 5 GB limit (adjust as needed)

# SECURITY CONFIGURATION
USE_HTTPS = True  # Enable HTTPS (recommended)
CERT_FILE = os.path.join(BASE_DIR, "nas_cert.pem")  # SSL certificate file
KEY_FILE = os.path.join(BASE_DIR, "nas_key.pem")    # SSL private key file
# Certificate identity (Common Name and SANs)
CERT_COMMON_NAME = "Yash Jain"
CERT_SANS = [
    "DNS:localhost",
    "IP:127.0.0.1",
    "DNS:yash5108"
]

# Optional password protection (leave empty to disable)
# IMPORTANT: Use a strong password and never commit this to version control!
NAS_PASSWORD = "#nas@yash*5108"  # Set to a password to enable authentication
# Store hashed password (SHA-256) instead of plaintext
NAS_PASSWORD_HASH = hashlib.sha256(NAS_PASSWORD.encode()).hexdigest() if NAS_PASSWORD else ""

# Session management
SESSION_TOKENS = {}  # Cache of valid session tokens {token: (timestamp, expiry)}
SESSION_TIMEOUT = 3600  # 1 hour session timeout
CSRF_TOKENS = {}  # CSRF token storage {session_token: csrf_token}

# Rate limiting for login attempts
LOGIN_ATTEMPTS = defaultdict(list)  # {ip: [timestamp1, timestamp2, ...]}
MAX_LOGIN_ATTEMPTS = 5  # Max attempts
LOGIN_WINDOW = 300  # 5 minutes in seconds
LOGIN_LOCKOUT = 900  # 15 minutes lockout

# Security logging
SECURITY_LOG_FILE = os.path.join(BASE_DIR, "nas_security.log")

# Generate secret key for CSRF tokens
SECRET_KEY = secrets.token_hex(32)

# Protect the running script and any filename you want hidden
SCRIPT_NAME = os.path.basename(__file__)
PROTECTED_FILES = {SCRIPT_NAME, "simple_nas.py"}  # add other filenames if needed
PROTECTED_PATHS = { os.path.abspath(os.path.join(DIRECTORY, n)) for n in PROTECTED_FILES }

# Hide files in the NAS container from web users
HIDE_DOTFILES = True
HIDDEN_FILES = {".gitkeep", "desktop.ini", "Thumbs.db"}
HIDDEN_EXTENSIONS = {".lnk"}

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

# SSE clients list and lock for notifying browser clients of filesystem changes
sse_clients = []
sse_lock = threading.Lock()

# Security helper functions
def log_security_event(event_type, details, ip="unknown"):
    """Log security events to file and console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{event_type}] IP:{ip} - {details}\n"
    safe_print(f"[SECURITY] {log_line.strip()}")
    try:
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        try:
            print(f"Warning: Could not write to security log: {e}")
        except UnicodeEncodeError:
            print(f"Warning: Could not write to security log")

def generate_csrf_token():
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(32)

def verify_csrf_token(session_token, csrf_token):
    """Verify CSRF token matches the session."""
    return CSRF_TOKENS.get(session_token) == csrf_token

def is_hidden_name(name):
    """Return True if a filename should be hidden from web users."""
    base = os.path.basename(name)
    if base in PROTECTED_FILES:
        return True
    if HIDE_DOTFILES and base.startswith('.'):
        return True
    if base in HIDDEN_FILES:
        return True
    _, ext = os.path.splitext(base)
    if ext.lower() in HIDDEN_EXTENSIONS:
        return True
    return False

def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_rate_limit(ip):
    """Check if IP is rate limited for login attempts."""
    now = time.time()
    attempts = LOGIN_ATTEMPTS[ip]
    
    # Remove old attempts outside the window
    LOGIN_ATTEMPTS[ip] = [t for t in attempts if now - t < LOGIN_WINDOW]
    
    # Check if locked out
    if len(LOGIN_ATTEMPTS[ip]) >= MAX_LOGIN_ATTEMPTS:
        oldest_attempt = min(LOGIN_ATTEMPTS[ip])
        if now - oldest_attempt < LOGIN_LOCKOUT:
            return False, LOGIN_LOCKOUT - int(now - oldest_attempt)
    
    return True, 0

def record_login_attempt(ip):
    """Record a failed login attempt."""
    LOGIN_ATTEMPTS[ip].append(time.time())

def generate_self_signed_cert(cert_file, key_file):
    """Generate a self-signed SSL certificate if it doesn't exist."""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return True
    
    try:
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "NAS Server"
        cert.get_subject().OU = "NAS"
        cert.get_subject().CN = CERT_COMMON_NAME
        cert.set_serial_number(secrets.randbits(64))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        # Add SANs (Subject Alternative Names)
        if CERT_SANS:
            san_value = ", ".join(CERT_SANS)
            cert.add_extensions([
                crypto.X509Extension(b"subjectAltName", False, san_value.encode("utf-8"))
            ])
        cert.sign(k, 'sha256')
        
        # Save certificate and key
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        safe_print(f"✓ Generated self-signed certificate: {cert_file}")
        return True
    except ImportError:
        safe_print("⚠️  PyOpenSSL not installed. Generating certificate using openssl command...")
        try:
            import subprocess
            san_value = ",".join(CERT_SANS)
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_file, "-out", cert_file,
                "-days", "365", "-nodes",
                "-subj", f"/C=US/ST=State/L=City/O=NAS/CN={CERT_COMMON_NAME}",
                "-addext", f"subjectAltName={san_value}"
            ], check=True, capture_output=True)
            safe_print(f"✓ Generated self-signed certificate: {cert_file}")
            return True
        except Exception as e:
            safe_print(f"❌ Could not generate certificate: {e}")
            safe_print("   Install PyOpenSSL: pip install pyopenssl")
            safe_print("   Or install OpenSSL command-line tool")
            return False
    except Exception as e:
        safe_print(f"❌ Error generating certificate: {e}")
        return False

class CustomRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler to add upload capabilities with security."""
    
    def handle_one_request(self):
        """Override to suppress harmless connection errors."""
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client closed connection or socket error — very common and harmless
            pass
        except Exception as e:
            # Log other exceptions normally
            print(f"[WARN] Request handler error: {type(e).__name__}: {e}")
    
    def end_headers(self):
        """Add security headers to all responses."""
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Content-Security-Policy', 
                        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'")
        if USE_HTTPS:
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        super().end_headers()
    
    def _get_auth_status(self):
        """Check if client is authenticated (returns True if auth disabled or client has valid token)."""
        if not NAS_PASSWORD:
            return True, None  # No password protection
        
        # Check for session token
        token = None
        if 'Cookie' in self.headers:
            import http.cookies
            cookie = http.cookies.SimpleCookie()
            cookie.load(self.headers['Cookie'])
            if 'nas_token' in cookie:
                token = cookie['nas_token'].value
        
        if token and token in SESSION_TOKENS:
            exp_time = SESSION_TOKENS[token]
            if time.time() < exp_time:
                return True, token  # Valid token
            else:
                del SESSION_TOKENS[token]  # Expired
                if token in CSRF_TOKENS:
                    del CSRF_TOKENS[token]
        
        return False, None
    
    def _serve_login_page(self):
        """Serve password login page."""
        html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NAS Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 32px;
        }
        .login-header h1 {
            font-size: 1.8rem;
            color: #333;
            margin-bottom: 4px;
        }
        .login-header p {
            color: #888;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #5568d3; }
        button:active { transform: scale(0.98); }
        #errorMsg {
            margin-top: 16px;
            padding: 12px;
            background: #fee;
            color: #c33;
            border-radius: 6px;
            display: none;
            text-align: center;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 NAS Access</h1>
            <p>Enter password to continue</p>
        </div>
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" autofocus required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div id="errorMsg"></div>
    </div>
    <script>
        function handleLogin(event) {
            event.preventDefault();
            var password = document.getElementById('password').value;
            var errorMsg = document.getElementById('errorMsg');
            var btn = event.target.querySelector('button');
            btn.disabled = true;
            btn.textContent = 'Checking...';
            
            fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password })
            })
            .then(r => r.json())
            .then(data => {
                if (data.token && data.csrf_token) {
                    // Store CSRF token in sessionStorage
                    sessionStorage.setItem('csrf_token', data.csrf_token);
                    errorMsg.style.display = 'none';
                    window.location.reload();
                } else {
                    errorMsg.textContent = data.error || 'Invalid password';
                    errorMsg.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Login';
                    document.getElementById('password').value = '';
                }
            })
            .catch(err => {
                errorMsg.textContent = 'Connection error';
                errorMsg.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Login';
            });
        }
    </script>
</body>
</html>'''
        html_bytes = html_content.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_bytes)))
        self.end_headers()
        self.wfile.write(html_bytes)
    
    def do_POST(self):
        """Handle file uploads and delete requests."""
        parsed = urllib.parse.urlparse(self.path)
        
        # Handle login
        if parsed.path == '/login':
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                password = data.get('password', '')
            except:
                self.send_json_response(400, {'error': 'Invalid JSON'})
                return
            
            client_ip = self.client_address[0]
            
            # Check rate limiting
            allowed, lockout_time = check_rate_limit(client_ip)
            if not allowed:
                log_security_event("LOGIN_RATE_LIMIT", f"Too many attempts, locked out for {lockout_time}s", client_ip)
                self.send_json_response(429, {'error': f'Too many attempts. Try again in {lockout_time} seconds'})
                return
            
            # Verify password (compare hashed values)
            password_hash = hash_password(password)
            if password_hash == NAS_PASSWORD_HASH:
                # Generate session token and CSRF token
                token = secrets.token_urlsafe(32)
                csrf_token = generate_csrf_token()
                SESSION_TOKENS[token] = time.time() + SESSION_TIMEOUT
                CSRF_TOKENS[token] = csrf_token
                
                log_security_event("LOGIN_SUCCESS", "User authenticated successfully", client_ip)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                # Secure cookie flags
                secure_flag = '; Secure' if USE_HTTPS else ''
                self.send_header('Set-Cookie', f'nas_token={token}; Path=/; HttpOnly; SameSite=Strict{secure_flag}')
                response = json.dumps({'token': token, 'csrf_token': csrf_token}).encode('utf-8')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                record_login_attempt(client_ip)
                log_security_event("LOGIN_FAILED", "Invalid password attempt", client_ip)
                self.send_json_response(403, {'error': 'Invalid password'})
            return
        
        # Check authentication for other POST operations
        is_auth, session_token = self._get_auth_status()
        if NAS_PASSWORD and not is_auth:
            self.send_json_response(401, {'error': 'Unauthorized'})
            return

        # Extract CSRF token (prefer header to avoid parsing multipart uploads)
        csrf_token = self.headers.get('X-CSRF-Token', '')
        data = None

        if parsed.path == '/delete':
            # Handle delete request (parse JSON once)
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
            except Exception:
                self.send_json_response(400, {'error': 'Invalid JSON'})
                return
            if not csrf_token:
                csrf_token = data.get('csrf_token', '')

        # Verify CSRF token for state-changing operations
        if NAS_PASSWORD and parsed.path != '/login':
            if not verify_csrf_token(session_token, csrf_token):
                log_security_event("CSRF_VIOLATION", f"Invalid CSRF token for {parsed.path}", self.client_address[0])
                self.send_json_response(403, {'error': 'CSRF token validation failed'})
                return

        if parsed.path == '/delete':
            filename = data.get('file', '')
            action = data.get('action', '')
            
            if action == 'request':
                # User requested to delete a file
                log_security_event("DELETE_REQUEST", f"File: {filename}", self.client_address[0])
                self._handle_delete_request(filename)
            elif action == 'confirm':
                # Server admin confirmed the delete
                token = data.get('token', '')
                log_security_event("DELETE_CONFIRM", f"File: {filename}, Token: {token}", self.client_address[0])
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

        # Protect/hidden files — immediate deny
        if is_hidden_name(safe_name):
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
        # Check authentication for protected paths
        is_auth, session_token = self._get_auth_status()
        if NAS_PASSWORD and not is_auth:
            # Show login page
            if self.path == '/' or self.path.startswith('/?'):
                return self._serve_login_page()
            # Redirect other requests to login
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        
        # Pass CSRF token to authenticated users
        self.csrf_token = CSRF_TOKENS.get(session_token, '') if session_token else ''
        
        parsed = urllib.parse.urlparse(self.path)
        # Server-Sent Events endpoint for live-reload
        if parsed.path == '/events':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()

            client = {'wfile': self.wfile, 'event': threading.Event()}
            with sse_lock:
                sse_clients.append(client)

            try:
                # Keep the connection open and write events when signaled
                while True:
                    client['event'].wait()
                    try:
                        client['wfile'].write(b"event: reload\ndata: 1\n\n")
                        client['wfile'].flush()
                    except Exception:
                        break
                    client['event'].clear()
            finally:
                with sse_lock:
                    if client in sse_clients:
                        sse_clients.remove(client)
            return
        
        # File preview endpoint
        if parsed.path == '/preview':
            qs = urllib.parse.parse_qs(parsed.query)
            if 'file' not in qs or not qs['file']:
                self.send_error(400, "Missing 'file' parameter")
                return
            fname = qs['file'][0]
            safe_name = os.path.basename(fname)
            
            if is_hidden_name(safe_name):
                self.send_error(404, "File not found")
                return
            
            file_path = os.path.join(DIRECTORY, safe_name)
            if not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return
            
            # Try to serve image preview for image files
            import mimetypes
            ctype, _ = mimetypes.guess_type(file_path)
            if ctype and ctype.startswith('image/'):
                try:
                    fs = os.path.getsize(file_path)
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(fs))
                    self.send_header("Cache-Control", "public, max-age=3600")
                    self.end_headers()
                    with open(file_path, 'rb') as f:
                        shutil.copyfileobj(f, self.wfile)
                except Exception as e:
                    self.send_error(500, f"Error serving preview: {e}")
            else:
                self.send_error(400, "Not an image file")
            return
        
        if parsed.path == '/download':
            qs = urllib.parse.parse_qs(parsed.query)
            if 'file' not in qs or not qs['file']:
                self.send_error(400, "Missing 'file' parameter")
                return
            fname = qs['file'][0]
            # sanitize filename
            safe_name = os.path.basename(fname)

            # Protect files from download
            if is_hidden_name(safe_name):
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

                    # Prevent uploads overwriting protected/hidden files
                    if is_hidden_name(fn):
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

/* ── Image thumbnails ── */
.file-thumbnail {
  width: 56px;
  height: 56px;
  border-radius: var(--radius-sm);
  object-fit: cover;
  border: 1px solid var(--border);
  flex-shrink: 0;
}

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

/* ── Contacts ── */
.contact-links { display: flex; flex-wrap: wrap; gap: 12px 18px; }
.contact-links a { color: var(--primary); text-decoration: none; font-weight: 500; }
.contact-links a:hover { text-decoration: underline; }

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
            if is_hidden_name(name):
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
                
                # Check if it's an image file for thumbnail preview
                import mimetypes
                ctype, _ = mimetypes.guess_type(fullname)
                is_image = ctype and ctype.startswith('image/')
                
                r.append('<li class="file-item">')
                if is_image:
                    # Show image thumbnail
                    thumb_url = "/preview?file=" + urllib.parse.quote(linkname)
                    r.append('<img src="%s" class="file-thumbnail" alt="%s">' % (thumb_url, html.escape(name)))
                else:
                    # Show file icon
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
        # Inject CSRF token into JavaScript
        if hasattr(self, 'csrf_token') and self.csrf_token:
            r.append(f'var CSRF_TOKEN = "{self.csrf_token}";')
            r.append('sessionStorage.setItem("csrf_token", CSRF_TOKEN);')
        else:
            r.append('var CSRF_TOKEN = sessionStorage.getItem("csrf_token") || "";')
        r.append('''
    var suppressReloadUntil = 0;

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
    xhr.setRequestHeader('X-CSRF-Token', CSRF_TOKEN);
    xhr.send(formData);
}

/* ── Delete ── */
function deleteFile(filename) {
    if (!confirm('Delete "' + filename + '"?')) return;

    // Avoid auto-reload immediately after delete
    suppressReloadUntil = Date.now() + 4000;

    var progressContainer = document.getElementById('progressContainer');
    var progressFill = document.getElementById('progressFill');
    var uploadStatus = document.getElementById('uploadStatus');

    progressContainer.style.display = 'block';
    uploadStatus.textContent = 'Requesting delete approval from server...';
    progressFill.style.width = '50%';
    progressFill.textContent = '...';

    fetch('/delete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSRF_TOKEN
        },
        body: JSON.stringify({file: filename, action: 'request', csrf_token: CSRF_TOKEN})
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
        # Add SSE-based live-reload listener
        r.append('''
    // Live-reload via Server-Sent Events
    if (window.EventSource) {
            var __es = new EventSource('/events');
            __es.addEventListener('reload', function(e) {
                if (Date.now() < suppressReloadUntil) return;
                try { window.location.reload(); } catch (e) {}
            });
      __es.onopen = function() { console.log('SSE connected'); };
      __es.onerror = function() { /* reconnect handled by browser */ console.log('SSE error'); };
    }
        ''')
        r.append('</script>')

        # Contacts section
        r.append('<div class="card">')
        r.append('<div class="card-title">📬 Contacts</div>')
        r.append('<div class="contact-links" style="display:flex;flex-wrap:wrap;gap:12px; font-size:0.9rem; justify-content:center; align-items:center;">')
        r.append('<a href="mailto:yash5108@gmail.com">Mail</a>')
        r.append('<a href="https://www.linkedin.com/in/yash-jain-540a9a271/" target="_blank" rel="noopener">LinkedIn</a>')
        r.append('<a href="https://github.com/Yash5108" target="_blank" rel="noopener">GitHub</a>')
        r.append('<a href="https://github.com/Yash5108/Python-Based-Local-NAS.git" target="_blank" rel="noopener">Project Repository</a>')
        r.append('</div>')
        r.append('</div>')

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
    
    # Create nas container directory if it doesn't exist
    if not os.path.exists(DIRECTORY):
        os.makedirs(DIRECTORY)
        safe_print(f"✓ Created NAS container directory: {DIRECTORY}")
    
    # ensure serving directory
    os.chdir(DIRECTORY)
    import socket

    # Helper to snapshot directory state (names, mtimes, sizes)
    def _dir_snapshot(root):
        snap = {}
        try:
            for name in os.listdir(root):
                if name in PROTECTED_FILES:
                    continue
                p = os.path.join(root, name)
                try:
                    stat = os.stat(p)
                    snap[name] = (stat.st_mtime, stat.st_size)
                except Exception:
                    snap[name] = None
        except Exception:
            pass
        return snap

    # Background watcher thread: polls for changes and notifies SSE clients
    def _watcher_thread():
        prev = _dir_snapshot(DIRECTORY)
        while True:
            try:
                time.sleep(1)
                curr = _dir_snapshot(DIRECTORY)
                if curr != prev:
                    with sse_lock:
                        for c in list(sse_clients):
                            try:
                                c['event'].set()
                            except Exception:
                                pass
                    prev = curr
            except Exception:
                # continue running even if watcher hits an error
                try:
                    time.sleep(1)
                except Exception:
                    pass

    # Start watcher thread
    watcher = threading.Thread(target=_watcher_thread, daemon=True)
    watcher.start()

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
            # Wrap with SSL if HTTPS is enabled
            if USE_HTTPS:
                if not generate_self_signed_cert(CERT_FILE, KEY_FILE):
                    safe_print("\n❌ Failed to generate SSL certificate. Falling back to HTTP.")
                    USE_HTTPS = False
                    PORT = 8000
                else:
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(CERT_FILE, KEY_FILE)
                        # Security: Use strong ciphers and TLS 1.2+
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
                        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                        log_security_event("SERVER_START", "HTTPS server started", "system")
                    except Exception as e:
                        safe_print(f"\n❌ SSL Error: {e}")
                        safe_print("   Falling back to HTTP...")
                        USE_HTTPS = False
                        PORT = 8000
            
            protocol = "https" if USE_HTTPS else "http"
            
            # Print startup summary
            safe_print("\n" + "="*70)
            safe_print("🔥 PYTHON NAS SERVER STARTED (SECURE)".center(70))
            safe_print("="*70)
            safe_print(f"\n📍 Server Address:  {bind_addr}:{PORT}")
            safe_print(f"📂 Directory:       {DIRECTORY}")
            safe_print(f"🔌 Max Threads:     Unlimited (ThreadingTCPServer)")
            safe_print(f"🔒 Protocol:        {protocol.upper()}")
            if USE_HTTPS:
                safe_print(f"📜 Certificate:     {CERT_FILE}")
                safe_print(f"🔑 Private Key:     {KEY_FILE}")
            if NAS_PASSWORD:
                safe_print(f"🔐 Authentication:  ENABLED (password protected)")
            else:
                safe_print(f"🔐 Authentication:  Disabled (open access - NOT RECOMMENDED)")
            safe_print(f"📊 Upload Limit:    {MAX_UPLOAD_SIZE / (1024*1024):.0f} MB" if MAX_UPLOAD_SIZE else "📊 Upload Limit:    Unlimited")
            safe_print(f"📝 Security Log:    {SECURITY_LOG_FILE}")
            safe_print("\n🌐 Access URLs:")
            safe_print(f"   Local:  {protocol}://localhost:{PORT}")
            safe_print(f"   LAN:    {protocol}://{local_ip}:{PORT}")
            if USE_HTTPS:
                safe_print(f"   ⚠️  Self-signed cert: Browsers will show security warning")
            safe_print(f"   ⚠️  Network access is on 0.0.0.0 — visible on LAN")
            safe_print("\n🛡️  Security Features:")
            if USE_HTTPS:
                safe_print("   ✓ HTTPS/TLS encryption")
                safe_print("   ✓ TLS 1.2+ with strong ciphers")
            safe_print("   ✓ Security headers (CSP, HSTS, X-Frame-Options)")
            safe_print("   ✓ CSRF protection")
            safe_print("   ✓ Password hashing (SHA-256)")
            safe_print("   ✓ Rate limiting (5 attempts per 5 min)")
            safe_print("   ✓ Secure session cookies")
            safe_print("   ✓ Input validation & upload limits")
            safe_print("   ✓ Security event logging")
            safe_print("\n💡 Features:")
            safe_print("   ✓ Upload files (drag & drop or click)")
            safe_print("   ✓ Download files with progress")
            safe_print("   ✓ Delete files (with server confirmation)")
            safe_print("   ✓ Live-reload (SSE)")
            safe_print("   ✓ Responsive mobile-friendly UI")
            if NAS_PASSWORD:
                safe_print("   ✓ Password protection")
            safe_print("\n⚠️  Note: Minor connection errors (WinError 10053) are normal.")
            safe_print("   These happen when browsers close connections rapidly.")
            safe_print("\n📋 Press Ctrl+C to stop the server")
            safe_print("="*70 + "\n")
            httpd.serve_forever()
    except KeyboardInterrupt:
        safe_print("\n\n" + "="*70)
        safe_print("🛑 SERVER STOPPED".center(70))
        safe_print("="*70 + "\n")
    except Exception as e:
        safe_print(f"\n❌ An error occurred: {e}")
        import traceback
        traceback.print_exc()


