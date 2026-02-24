# Secure NAS Server - Setup Guide

## Quick Start

### 1. Install Dependencies (Optional but Recommended)

For automatic SSL certificate generation, install PyOpenSSL:
```bash
pip install pyopenssl
```

Alternatively, ensure OpenSSL command-line tool is installed on your system.

### 2. Configure Password (Recommended)

Edit `simple_nas.py` and set a strong password:

```python
NAS_PASSWORD = "YourStrongPasswordHere123!"
```

**Important**: 
- Use at least 12 characters
- Mix uppercase, lowercase, numbers, and special characters
- Never commit this file with passwords to version control
- Consider using environment variables for production

### 3. Run the Server

```bash
py simple_nas.py
```

On first run, the server will:
- Generate a self-signed SSL certificate (nas_cert.pem)
- Generate a private key (nas_key.pem)
- Start listening on port 8443 (HTTPS)

### 4. Access the Server

Open your browser and navigate to:
- Local: `https://localhost:8443`
- LAN: `https://YOUR_IP:8443`

**Note**: You'll see a security warning because of the self-signed certificate. This is normal. Click "Advanced" and "Proceed to localhost" (or similar).

### 5. Login

Enter the password you configured in step 2.

## Configuration Options

### Change Port

```python
PORT = 8443  # Change to your preferred port (e.g., 443 for standard HTTPS)
```

### Disable HTTPS (Not Recommended)

```python
USE_HTTPS = False  # Falls back to HTTP on port 8000
```

### Adjust Upload Limits

```python
MAX_UPLOAD_SIZE = 5120 * 1024 * 1024  # 5 GB (change as needed)
```

### Disable Authentication (Not Recommended)

```python
NAS_PASSWORD = ""  # Leave empty to disable authentication
```

### Session Timeout

```python
SESSION_TIMEOUT = 3600  # 1 hour in seconds (change as needed)
```

### Rate Limiting

```python
MAX_LOGIN_ATTEMPTS = 5  # Max failed login attempts
LOGIN_WINDOW = 300      # Time window (5 minutes)
LOGIN_LOCKOUT = 900     # Lockout duration (15 minutes)
```

## Troubleshooting

### Certificate Generation Failed

**Symptoms**: Server shows error about SSL certificate generation

**Solutions**:
1. Install PyOpenSSL: `pip install pyopenssl`
2. Or install OpenSSL CLI:
   - Windows: https://slproweb.com/products/Win32OpenSSL.html
   - Linux: `sudo apt-get install openssl`
   - Mac: `brew install openssl`

### Browser Shows Security Warning

**This is normal** for self-signed certificates. Options:
1. Click "Advanced" → "Proceed to localhost" (acceptable for local use)
2. Use production certificates (see Production Setup below)
3. Import the certificate to your browser's trusted certificates

### Cannot Access from Other Devices

**Check**:
1. Firewall settings (allow port 8443)
2. Server is binding to 0.0.0.0 (check startup message)
3. Both devices are on the same network
4. Use the correct IP address (shown in startup message)

### Rate Limited / Locked Out

**Wait** 15 minutes and try again, or:
1. Restart the server (clears rate limit counters)
2. Adjust rate limiting settings

### "CSRF token validation failed"

**Causes**:
- Session expired (15-minute inactivity)
- Browser cache issues

**Solutions**:
1. Refresh the page and login again
2. Clear browser cache and cookies
3. Use incognito/private mode

## Production Setup

### 1. Use a Proper Certificate

**Option A: Let's Encrypt (Free, Automated)**
```bash
# Install certbot
sudo apt-get install certbot  # Linux
brew install certbot          # Mac

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nas_cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nas_key.pem
sudo chown $USER:$USER nas_*.pem
```

**Option B: Purchase from CA**
- Buy certificate from CA (DigiCert, Comodo, etc.)
- Follow CA instructions to generate CSR
- Replace `nas_cert.pem` and `nas_key.pem` with your certificates

### 2. Use Environment Variables for Password

Instead of hardcoding:
```python
import os
NAS_PASSWORD = os.environ.get('NAS_PASSWORD', '')
```

Then run:
```bash
export NAS_PASSWORD="YourStrongPassword"
python simple_nas.py
```

### 3. Run as a Service

**Linux (systemd)**:

Create `/etc/systemd/system/nas.service`:
```ini
[Unit]
Description=Secure NAS Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/nas
Environment="NAS_PASSWORD=YourPassword"
ExecStart=/usr/bin/python3 /path/to/nas/simple_nas.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable nas
sudo systemctl start nas
sudo systemctl status nas
```

**Windows (NSSM)**:
```bash
# Download NSSM from nssm.cc
nssm install NASServer "C:\Path\To\python.exe" "C:\Path\To\simple_nas.py"
nssm set NASServer AppDirectory "C:\Path\To"
nssm set NASServer AppEnvironmentExtra NAS_PASSWORD=YourPassword
nssm start NASServer
```

### 4. Configure Firewall

**Linux (ufw)**:
```bash
sudo ufw allow 8443/tcp
sudo ufw enable
```

**Windows (PowerShell as Admin)**:
```powershell
New-NetFirewallRule -DisplayName "NAS Server" -Direction Inbound -LocalPort 8443 -Protocol TCP -Action Allow
```

### 5. Use Reverse Proxy (Optional)

**Nginx Example**:
```nginx
server {
    listen 443 ssl;
    server_name nas.yourdomain.com;
    
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    location / {
        proxy_pass https://localhost:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Checklist

Before deploying:

- [ ] Set a strong password (12+ characters)
- [ ] HTTPS is enabled (`USE_HTTPS = True`)
- [ ] Upload size limits configured appropriately
- [ ] Firewall rules configured
- [ ] Using production certificates (not self-signed)
- [ ] Password stored as environment variable (not in code)
- [ ] Regular backups configured
- [ ] Security log monitoring set up
- [ ] Only necessary ports exposed
- [ ] Server running with non-root user

## Monitoring

### Check Security Logs

```bash
# View recent events
tail -f nas_security.log

# Count failed login attempts
grep "LOGIN_FAILED" nas_security.log | wc -l

# Find rate limit violations
grep "LOGIN_RATE_LIMIT" nas_security.log
```

### Monitor Server Status

```bash
# Check if server is running (Linux)
ps aux | grep simple_nas.py

# Check port (Linux)
netstat -tlnp | grep 8443

# Check port (Windows)
netstat -an | findstr "8443"
```

### Log Rotation (Recommended)

**Linux (logrotate)**:

Create `/etc/logrotate.d/nas`:
```
/path/to/nas_security.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 your-user your-group
}
```

## Common Use Cases

### 1. Home Network File Server
- Enable password protection
- Use self-signed certificate (browser warnings are acceptable)
- Restrict firewall to local network only
- Set reasonable upload limits

### 2. Small Office Server
- Use Let's Encrypt certificate
- Strong password or consider multi-user authentication
- Set up regular backups
- Monitor security logs weekly
- Configure fail2ban for additional protection

### 3. Public Access (Shared Files)
- Use production SSL certificate
- Consider disabling authentication OR use very strong password
- Implement strict upload limits
- Monitor logs daily
- Use rate limiting aggressively
- Consider additional layers (VPN, IP whitelist)

## Performance Tuning

### For Large Files
```python
MAX_UPLOAD_SIZE = 5 * 1024 * 1024 * 1024  # 5 GB
```

### For Many Concurrent Users
- Consider using a production WSGI server (gunicorn, uwsgi)
- Implement connection pooling
- Add caching layer

### For Slow Networks
- Reduce session timeout for security
- Implement resumable uploads
- Add compression

## Backup & Recovery

### Backup Important Files
```bash
# Backup certificates
cp nas_cert.pem nas_cert.pem.backup
cp nas_key.pem nas_key.pem.backup

# Backup configuration (without passwords!)
grep -v "NAS_PASSWORD" simple_nas.py > simple_nas.py.backup

# Backup security logs
cp nas_security.log nas_security.log.$(date +%Y%m%d)
```

### Recovery
1. Restore certificates
2. Restore configuration
3. Set password via environment variable
4. Restart server

## Support

- **Documentation**: See [SECURITY.md](SECURITY.md) for detailed security information
- **Logs**: Check `nas_security.log` for security events
- **Issues**: Review common issues in Troubleshooting section

---
**Version**: 2.0 (Secure)  
**Last Updated**: 2026-02-24
