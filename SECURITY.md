# Security Features Documentation

## Overview
This document describes the security enhancements implemented in the NAS server to protect against common web vulnerabilities and ensure secure file sharing.

## Security Improvements Implemented

### 1. HTTPS/TLS Encryption 🔒
- **Feature**: All traffic is encrypted using HTTPS with TLS 1.2+
- **Implementation**: 
  - Self-signed SSL certificate generation (automatic)
  - Strong cipher suites: `ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20`
  - Minimum TLS version: TLS 1.2
- **Configuration**: 
   - `USE_HTTPS = True` (enable/disable)
   - `PORT = 8443` (default HTTPS port)
   - `CERT_FILE = "nas_cert.pem"` (certificate path, stored in project root)
   - `KEY_FILE = "nas_key.pem"` (private key path, stored in project root)
- **Protection**: Prevents eavesdropping, man-in-the-middle attacks, and password sniffing

### 2. Secure Password Handling 🔐
- **Feature**: Passwords are never stored in plaintext
- **Implementation**: 
  - SHA-256 password hashing
  - Hash comparison instead of plaintext comparison
  - `NAS_PASSWORD_HASH` stores the hashed password
- **Protection**: Even if the code is exposed, the actual password remains secret

### 3. Rate Limiting ⏱️
- **Feature**: Prevents brute force attacks on login
- **Implementation**:
  - Maximum 5 login attempts per IP address
  - 5-minute rolling window for attempt tracking
  - 15-minute lockout after exceeding limit
- **Configuration**:
  - `MAX_LOGIN_ATTEMPTS = 5`
  - `LOGIN_WINDOW = 300` (seconds)
  - `LOGIN_LOCKOUT = 900` (seconds)
- **Protection**: Blocks automated password guessing attacks

### 4. CSRF Protection 🛡️
- **Feature**: Prevents Cross-Site Request Forgery attacks
- **Implementation**:
  - Unique CSRF token generated per session
  - Token validated on all state-changing operations (delete, upload)
  - Token stored in sessionStorage on client
- **Protection**: Prevents malicious websites from performing actions on behalf of authenticated users

### 5. Security Headers 📋
All responses include security-hardening HTTP headers:
- **X-Content-Type-Options**: `nosniff` - Prevents MIME type sniffing
- **X-Frame-Options**: `DENY` - Prevents clickjacking attacks
- **X-XSS-Protection**: `1; mode=block` - Enables XSS filter
- **Referrer-Policy**: `strict-origin-when-cross-origin` - Controls referrer information
- **Content-Security-Policy**: Restricts resource loading to prevent XSS
- **Strict-Transport-Security**: Forces HTTPS (when enabled)

### 6. Secure Session Management 🎫
- **Feature**: Secure session cookies with proper flags
- **Implementation**:
  - `HttpOnly` flag - Prevents JavaScript access to cookies
  - `Secure` flag - Cookies only sent over HTTPS
  - `SameSite=Strict` - Prevents CSRF via cookies
  - Session timeout: 1 hour (configurable)
  - Cryptographically secure token generation
- **Protection**: Prevents session hijacking and XSS-based cookie theft

### 7. Input Validation & Upload Limits 📏
- **Feature**: Prevents resource exhaustion and malicious uploads
- **Implementation**:
   - Maximum upload size: 5 GB (configurable)
  - File path sanitization using `os.path.basename()`
  - Protected files list to prevent critical file overwrites
- **Configuration**:
   - `MAX_UPLOAD_SIZE = 5120 * 1024 * 1024` (bytes)
  - `PROTECTED_FILES` = set of protected filenames
- **Protection**: Prevents DoS attacks and file system manipulation

### 8. Security Event Logging 📝
- **Feature**: Comprehensive audit trail of security events
- **Implementation**:
  - Logs all login attempts (success/failure)
  - Logs rate limit violations
  - Logs CSRF validation failures
  - Logs file deletion requests
  - Timestamp and IP address tracking
- **Log File**: `nas_security.log`
- **Protection**: Enables security monitoring and incident response

### 9. Protected File System 🗂️
- **Feature**: Prevents access to sensitive files
- **Implementation**:
  - Script file (simple_nas.py) is hidden from file listing
  - Protected files cannot be downloaded, deleted, or overwritten
  - Windows hidden attribute set on protected files (Windows only)
- **Protection**: Prevents server configuration exposure or accidental deletion

## Security Best Practices

### For Server Administrators

1. **Set a Strong Password**:
   ```python
   NAS_PASSWORD = "YourStrongPasswordHere123!"
   ```
   - Use at least 12 characters
   - Mix uppercase, lowercase, numbers, and symbols
   - Never commit password to version control

2. **Use Production Certificates**:
   - For production, replace self-signed certificates with CA-issued certificates
   - Use Let's Encrypt for free certificates
   - Configure proper domain names

3. **Configure Firewall**:
   - Only expose the NAS port to trusted networks
   - Use firewall rules to restrict access by IP
   - Consider VPN for remote access

4. **Monitor Security Logs**:
   - Regularly check `nas_security.log`
   - Look for suspicious login patterns
   - Investigate CSRF violations

5. **Keep Software Updated**:
   - Update Python regularly
   - Update dependencies (if any are added)
   - Monitor security advisories

6. **Adjust Upload Limits**:
   ```python
   MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # Adjust based on needs
   ```

### For Users

1. **Verify HTTPS**:
   - Always check for the padlock icon in browser
   - For self-signed certificates, verify the fingerprint

2. **Use Strong Passwords**:
   - Don't share your NAS password
   - Use a password manager

3. **Logout When Done**:
   - Sessions expire after 1 hour
   - Close browser when using shared computers

4. **Verify URLs**:
   - Always use the correct server URL
   - Don't click suspicious links

## Certificate Generation

### Automatic Generation
The server automatically generates self-signed certificates on first run. Two methods are tried:

1. **PyOpenSSL** (preferred):
   ```bash
   pip install pyopenssl
   ```

2. **OpenSSL CLI** (fallback):
   - Windows: Install from https://slproweb.com/products/Win32OpenSSL.html
   - Linux/Mac: Usually pre-installed

### Manual Generation
```bash
openssl req -x509 -newkey rsa:2048 -keyout nas_key.pem -out nas_cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=NAS/CN=localhost"
```

### Production Certificates
For production use with domain names:
```bash
# Using certbot (Let's Encrypt)
certbot certonly --standalone -d yourdomain.com
# Then copy the certificates
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nas_cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nas_key.pem
```

## Threat Model

### Protected Against ✅
- ✅ Password sniffing (HTTPS encryption)
- ✅ Man-in-the-middle attacks (TLS)
- ✅ Brute force attacks (rate limiting)
- ✅ CSRF attacks (CSRF tokens)
- ✅ XSS attacks (CSP headers, input sanitization)
- ✅ Clickjacking (X-Frame-Options)
- ✅ Session hijacking (secure cookies, HTTPS)
- ✅ Path traversal (path sanitization)
- ✅ Resource exhaustion (upload limits)

### Known Limitations ⚠️
- ⚠️ Self-signed certificates trigger browser warnings (use CA certificates in production)
- ⚠️ No protection against compromised client machines
- ⚠️ Single password for all users (consider multi-user system for teams)
- ⚠️ No end-to-end encryption for files at rest
- ⚠️ Session management is memory-based (lost on server restart)
- ⚠️ No protection against physical server access

## Configuration Reference

```python
# Server Configuration
PORT = 8443                           # HTTPS port
DIRECTORY = os.getcwd()               # NAS root directory

# Security Configuration
USE_HTTPS = True                      # Enable HTTPS
CERT_FILE = "nas_cert.pem"           # SSL certificate
KEY_FILE = "nas_key.pem"             # SSL private key
NAS_PASSWORD = ""                     # Access password
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500 MB limit

# Session Management
SESSION_TIMEOUT = 3600                # 1 hour (seconds)

# Rate Limiting
MAX_LOGIN_ATTEMPTS = 5                # Max failed attempts
LOGIN_WINDOW = 300                    # 5 minutes (seconds)
LOGIN_LOCKOUT = 900                   # 15 minutes (seconds)

# Logging
SECURITY_LOG_FILE = "nas_security.log"  # Security event log
```

## Compliance Considerations

### GDPR (General Data Protection Regulation)
- ✅ Secure data transmission (HTTPS)
- ✅ Access controls (password protection)
- ✅ Audit trail (security logging)
- ⚠️ Consider data retention policies for logs
- ⚠️ Implement user consent mechanisms if storing personal data

### ISO 27001 (Information Security Management)
- ✅ Access control (authentication, authorization)
- ✅ Cryptographic controls (TLS, password hashing)
- ✅ Security logging and monitoring
- ✅ Secure development practices
- ⚠️ Implement formal security policies and procedures

## Incident Response

### If You Suspect a Security Breach

1. **Immediate Actions**:
   - Stop the server (`Ctrl+C`)
   - Change the password
   - Review `nas_security.log`
   - Check for unauthorized file access/changes

2. **Investigation**:
   - Identify the attack vector
   - Determine what data was accessed
   - Review all security logs

3. **Recovery**:
   - Generate new SSL certificates
   - Update passwords
   - Review and update firewall rules
   - Restart server with enhanced monitoring

4. **Prevention**:
   - Apply relevant security patches
   - Adjust rate limiting if needed
   - Consider additional access restrictions

## Additional Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Mozilla Security Guidelines: https://infosec.mozilla.org/guidelines/web_security
- Let's Encrypt: https://letsencrypt.org/
- Python Security Best Practices: https://python.readthedocs.io/en/stable/library/security_warnings.html

## Support & Questions

For security concerns or questions:
- Review this documentation
- Check the security log file
- Consult Python security resources
- Consider professional security audit for production use

---
**Last Updated**: 2026-02-24  
**Version**: 2.0 (Secure)
