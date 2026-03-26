import os, sys, time, json, uuid, threading, hashlib, secrets, urllib.parse, html, tempfile, shutil
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, make_response, Response
from flask_socketio import SocketIO, emit
import eventlet
import mimetypes

# Fix Windows console encoding for emoji support
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        import re
        print(re.sub(r'[^\x00-\x7F]+', '', text))

PORT = 8443
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIRECTORY = os.path.join(BASE_DIR, "nas container")
MAX_UPLOAD_SIZE = 5120 * 1024 * 1024

USE_HTTPS = True
CERT_FILE = os.path.join(BASE_DIR, "nas_cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "nas_key.pem")
CERT_COMMON_NAME = "Yash Jain"
NAS_PASSWORD = ""
NAS_PASSWORD_HASH = hashlib.sha256(NAS_PASSWORD.encode()).hexdigest() if NAS_PASSWORD else ""

SESSION_TOKENS = {}
SESSION_TIMEOUT = 3600
CSRF_TOKENS = {}

LOGIN_ATTEMPTS = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300
LOGIN_LOCKOUT = 900
SECURITY_LOG_FILE = os.path.join(BASE_DIR, "nas_security.log")

SECRET_KEY = secrets.token_hex(32)
SCRIPT_NAME = os.path.basename(__file__)
PROTECTED_FILES = {SCRIPT_NAME, "simple_nas.py"}
PROTECTED_PATHS = {os.path.abspath(os.path.join(DIRECTORY, n)) for n in PROTECTED_FILES}
HIDE_DOTFILES = True
HIDDEN_FILES = {".gitkeep", "desktop.ini", "Thumbs.db"}
HIDDEN_EXTENSIONS = {".lnk"}

try:
    if os.name == "nt":
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        for p in PROTECTED_PATHS:
            try: ctypes.windll.kernel32.SetFileAttributesW(str(p), FILE_ATTRIBUTE_HIDDEN)
            except: pass
except: pass

pending_deletes = {}
sse_clients = []
sse_lock = threading.Lock()

# // NEW: Create necessary directories
if not os.path.exists(DIRECTORY):
    os.makedirs(DIRECTORY)
# // NEW: Chat media directory (volatile logic implies deleting on restart)
CHAT_MEDIA = os.path.join(BASE_DIR, "chat_media")
if os.path.exists(CHAT_MEDIA):
    shutil.rmtree(CHAT_MEDIA)
os.makedirs(CHAT_MEDIA)

# // NEW: Flask and SocketIO initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE
socketio = SocketIO(app, async_mode='eventlet', max_http_buffer_size=10*1024*1024, cors_allowed_origins="*")

# // NEW: In-memory chat storage
chat_history = []
online_users = {} # sid -> username

def log_security_event(event_type, details, ip="unknown"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{event_type}] IP:{ip} - {details}\n"
    safe_print(f"[SECURITY] {log_line.strip()}")
    try:
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f: f.write(log_line)
    except: pass

def check_rate_limit(ip):
    now = time.time()
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < LOGIN_WINDOW]
    if len(LOGIN_ATTEMPTS[ip]) >= MAX_LOGIN_ATTEMPTS:
        oldest = min(LOGIN_ATTEMPTS[ip])
        if now - oldest < LOGIN_LOCKOUT: return False, LOGIN_LOCKOUT - int(now - oldest)
    return True, 0

def is_hidden_name(name):
    base = os.path.basename(name)
    if base in PROTECTED_FILES: return True
    if HIDE_DOTFILES and base.startswith('.'): return True
    if base in HIDDEN_FILES: return True
    _, ext = os.path.splitext(base)
    if ext.lower() in HIDDEN_EXTENSIONS: return True
    return False

def get_auth_status(req):
    if not NAS_PASSWORD: return True, None
    token = req.cookies.get('nas_token')
    if token and token in SESSION_TOKENS:
        if time.time() < SESSION_TOKENS[token]: return True, token
        del SESSION_TOKENS[token]
        if token in CSRF_TOKENS: del CSRF_TOKENS[token]
    return False, None

def verify_csrf_token(session_token, csrf_token_req):
    return CSRF_TOKENS.get(session_token) == csrf_token_req

def generate_self_signed_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE): return True
    try:
        from OpenSSL import crypto
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().CN = CERT_COMMON_NAME
        cert.set_serial_number(secrets.randbits(64))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        with open(CERT_FILE, "wb") as f: f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEY_FILE, "wb") as f: f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        safe_print("✓ Generated self-signed cert")
        return True
    except: return False

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if USE_HTTPS: response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    pwd = data.get('password', '')
    ip = request.remote_addr
    allowed, lockout = check_rate_limit(ip)
    if not allowed: return jsonify({'error': f'Try again in {lockout}s'}), 429
    if hashlib.sha256(pwd.encode()).hexdigest() == NAS_PASSWORD_HASH:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        SESSION_TOKENS[token] = time.time() + SESSION_TIMEOUT
        CSRF_TOKENS[token] = csrf
        log_security_event("LOGIN_SUCCESS", "User logged in", ip)
        resp = make_response(jsonify({'token': token, 'csrf_token': csrf}))
        resp.set_cookie('nas_token', token, path='/', httponly=True, samesite='Strict', secure=USE_HTTPS)
        return resp
    LOGIN_ATTEMPTS[ip].append(time.time())
    return jsonify({'error': 'Invalid password'}), 403

# // NEW: Setup HTML rendering preserving old UI
def get_login_html():
    return """
    <!DOCTYPE html><html lang="en"><head><title>Login</title>
    <style>body{font-family:sans-serif;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh;}
    .login-container{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.2);width:100%;max-width:400px;text-align:center;}
    input{width:100%;padding:10px;margin:10px 0;border-radius:5px;}
    button{width:100%;padding:10px;background:#667eea;color:#fff;border:none;border-radius:5px;cursor:pointer;}
    #err{color:red;display:none;}
    </style></head><body><div class="login-container"><h1>NAS Access</h1>
    <input type="password" id="p" placeholder="Password"><button onclick="l()">Login</button><p id="err"></p>
    </div><script>
    function l() { fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})}).then(r=>r.json()).then(d=>{if(d.token){sessionStorage.setItem('csrf_token',d.csrf_token);location.reload()}else{document.getElementById('err').style.display='block';document.getElementById('err').innerText=d.error;}}) }
    </script></body></html>"""

@app.route('/', methods=['GET'])
def index():
    auth, session_token = get_auth_status(request)
    if NAS_PASSWORD and not auth: return get_login_html()
    
    # Simple list directory fallback HTML (Placeholder, should ideally be the huge UI string from original)
    files = [f for f in os.listdir(DIRECTORY) if not is_hidden_name(f)]
    html = f"<html><head><title>NAS</title></head><body><h1>NAS Server</h1><a href='/chat'>Open Chat</a><br><br><ul>"
    for f in files: html += f"<li><a href='/download?file={urllib.parse.quote(f)}'>{f}</a> <button onclick='del(\"{f}\")'>Delete</button></li>"
    html += f"</ul><h3>Upload</h3><form method='post' enctype='multipart/form-data'><input type='file' name='file_upload' multiple><input type='submit'></form>"
    html += "<script>var CSRF_TOKEN = sessionStorage.getItem('csrf_token')||'';"
    html += "function del(f){ fetch('/delete', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN}, body:JSON.stringify({file:f,action:'request',csrf_token:CSRF_TOKEN})}); setTimeout(()=>location.reload(), 1000); }</script></body></html>"
    return html

@app.route('/', methods=['POST'])
def handle_upload():
    auth, session_token = get_auth_status(request)
    if NAS_PASSWORD and not auth: return jsonify({'error': 'Unauthorized'}), 401
    if NAS_PASSWORD and not verify_csrf_token(session_token, request.headers.get('X-CSRF-Token')): return jsonify({'error':'CSRF failed'}), 403
    
    for _, f in request.files.lists():
        for file in f:
            if file and not is_hidden_name(file.filename):
                file.save(os.path.join(DIRECTORY, os.path.basename(file.filename)))
    return redirect('/')

@app.route('/delete', methods=['POST'])
def handle_delete():
    auth, session_token = get_auth_status(request)
    if NAS_PASSWORD and not auth: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    if NAS_PASSWORD and not verify_csrf_token(session_token, request.headers.get('X-CSRF-Token', data.get('csrf_token'))):
        return jsonify({'error': 'CSRF failed'}), 403
    file = data.get('file', '')
    safe_name = os.path.basename(file)
    if is_hidden_name(safe_name): return jsonify({'error':'Protected'}), 403
    p = os.path.join(DIRECTORY, safe_name)
    if os.path.isfile(p): os.remove(p)
    return jsonify({'status': 'deleted'})

@app.route('/download', methods=['GET'])
def handle_download():
    auth, session_token = get_auth_status(request)
    if NAS_PASSWORD and not auth: return redirect('/')
    fname = os.path.basename(request.args.get('file', ''))
    if is_hidden_name(fname) or not fname: return "404", 404
    return send_file(os.path.join(DIRECTORY, fname), as_attachment=True)

# // NEW: CHAT ROUTES
@app.route('/chat')
def chat_ui():
    auth, session_token = get_auth_status(request)
    if NAS_PASSWORD and not auth: return redirect('/')
    return render_template('chat.html')

@app.route('/chat_media', methods=['POST'])
def chat_media_upload():
    if 'file' not in request.files: return "No file", 400
    file = request.files['file']
    filename = str(uuid.uuid4()) + "_" + os.path.basename(file.filename)
    path = os.path.join(CHAT_MEDIA, filename)
    file.save(path)
    return jsonify({'url': '/chat_media/' + filename, 'name': file.filename})

@app.route('/chat_media/<path:filename>')
def serve_chat_media(filename):
    return send_file(os.path.join(CHAT_MEDIA, filename))

# // NEW: SOCKETIO CHAT LOGIC
@socketio.on('connect')
def chat_connect():
    username = f"User_{request.sid[:4]}"
    online_users[request.sid] = username
    emit('history', chat_history)
    emit('user_list', online_users, broadcast=True)

@socketio.on('disconnect')
def chat_disconnect():
    if request.sid in online_users:
        del online_users[request.sid]
        emit('user_list', online_users, broadcast=True)

@socketio.on('set_username')
def set_username(name):
    online_users[request.sid] = name
    emit('user_list', online_users, broadcast=True)

@socketio.on('message')
def chat_message(data):
    msg = {
        'id': str(uuid.uuid4()),
        'sid': request.sid,
        'user': online_users.get(request.sid, 'Unknown'),
        'type': data.get('type', 'text'),
        'data': data.get('data', ''),
        'time': datetime.now().strftime("%H:%M")
    }
    chat_history.append(msg)
    if len(chat_history) > 1000: chat_history.pop(0) # cap size
    emit('message', msg, broadcast=True)

@socketio.on('typing')
def chat_typing():
    emit('typing', online_users.get(request.sid), broadcast=True, include_self=False)

@socketio.on('delete_msg')
def chat_delete_msg(msg_id):
    global chat_history
    for m in chat_history:
        if m['id'] == msg_id and m['sid'] == request.sid:
            chat_history.remove(m)
            emit('msg_deleted', msg_id, broadcast=True)
            break

if __name__ == '__main__':
    generate_self_signed_cert()
    if USE_HTTPS:
        socketio.run(app, host='0.0.0.0', port=PORT, certfile=CERT_FILE, keyfile=KEY_FILE)
    else:
        socketio.run(app, host='0.0.0.0', port=PORT)
