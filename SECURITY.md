# Security Features Documentation

## Overview
This document describes the security enhancements implemented in the NAS server to protect against common web vulnerabilities, resource starvation, and Denial of Service (DoS) attacks.

## Security Improvements Implemented

### 1. HTTPS/TLS Encryption & Starvation Prevention 🔒
- **Feature**: All traffic is encrypted using HTTPS with TLS 1.2+
- **Implementation**: 
  - Self-signed SSL certificate generation (automatic) with PATH diagnostics for `openssl` binary.
  - Strong cipher suites: `ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20`
  - Minimum TLS version: TLS 1.2
  - **Starvation Protection**: TLS handshakes are wrapped **in-thread** inside connection worker threads.
- **Protection**: Prevents eavesdropping and MITM attacks. Importantly, prevents socket starvation DoS where a client stalls the TLS handshake to freeze the main server listener.

### 2. Secure Password Handling 🔐
- **Feature**: Passwords are never stored in plaintext
- **Implementation**: 
  - SHA-256 password hashing
  - Hash comparison instead of plaintext comparison
  - `NAS_PASSWORD_HASH` stores the hashed password
- **Protection**: Even if the code is exposed, the actual password remains secret.

### 3. Rate Limiting & Lock Synchronization ⏱️
- **Feature**: Prevents brute force attacks on login
- **Implementation**:
  - Maximum 5 login attempts per IP address
  - 5-minute rolling window for attempt tracking
  - 15-minute lockout after exceeding limit
  - **Thread-Safety**: Login records and attempt trackers are synchronized via `login_lock`.
- **Configuration**:
  - `MAX_LOGIN_ATTEMPTS = 5`
  - `LOGIN_WINDOW = 300` (seconds)
  - `LOGIN_LOCKOUT = 900` (seconds)
- **Protection**: Blocks automated brute force guessing attacks safely across concurrent threads.

### 4. CSRF Protection 🛡️
- **Feature**: Prevents Cross-Site Request Forgery attacks
- **Implementation**:
  - Unique CSRF token generated per session
  - Token validated on all state-changing operations (delete, upload)
  - Token stored in sessionStorage on client
  - **Thread-Safety**: Access to CSRF registers is synchronized via `session_lock`.
- **Protection**: Prevents third-party malicious websites from performing operations on behalf of authenticated users.

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
  - **Thread-Safety**: Session verification and expiry are synchronized via `session_lock`.
- **Protection**: Prevents session hijacking and XSS-based cookie theft.

### 7. Input Validation & Memory-Safe Upload Limits 📏
- **Feature**: Prevents resource exhaustion and malicious uploads
- **Implementation**:
  - Maximum upload size: 5 GB (configurable)
  - File path sanitization using `os.path.basename()`
  - Protected files list to prevent critical file overwrites
  - **Memory-Safe Fallback Parser**: If standard library `cgi` is missing (e.g. Python 3.13+), a streaming parser reads the request in **64KB chunks** and writes directly to disk.
- **Protection**: Prevents path traversal vulnerabilities and Out-Of-Memory (OOM) Denial of Service crashes during large file uploads.

### 8. Security Event Logging 📝
- **Feature**: Comprehensive audit trail of security events
- **Implementation**:
  - Logs all login attempts (success/failure)
  - Logs rate limit violations
  - Logs CSRF validation failures
  - Logs file deletion requests
  - Logs SSL/TLS handshake exceptions
- **Log File**: `nas_security.log`
- **Protection**: Enables security monitoring and incident response.

### 9. Protected File System 🗂️
- **Feature**: Prevents access to sensitive files
- **Implementation**:
  - Script file (`nas.py`) is hidden from file listing
  - Protected files cannot be downloaded, deleted, or overwritten
- **Protection**: Prevents server configuration exposure or accidental deletion.

### 10. Concurrency Security & Denial of Service (DoS) Protections ⚡
- **Thread-Safe State**: All shared collections (`SESSION_TOKENS`, `CSRF_TOKENS`, `LOGIN_ATTEMPTS`, `pending_deletes`) are synchronized using dedicated thread locks (`session_lock`, `login_lock`, `delete_lock`).
- **SSE Thread Leak Prevention**: Server-Sent Events `/events` endpoint utilizes a 60-second wait timeout and writes a heartbeat (`:heartbeat\n\n`) to identify and tear down dead connections immediately.
- **SSE Connection Culling**: Auto-disconnects SSE client connections after 5 minutes to release system resources.

---

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

---

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
- ✅ Resource exhaustion (upload limits, chunked streaming parser)
- ✅ Socket starvation DoS (in-thread SSL wrapping)
- ✅ Thread leak DoS (SSE heartbeats and culling)

### Known Limitations ⚠️
- ⚠️ Self-signed certificates trigger browser warnings (use CA certificates in production)
- ⚠️ Single password for all users (consider multi-user system for teams)
- ⚠️ No end-to-end encryption for files at rest
- ⚠️ Session management is memory-based (lost on server restart)

---

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

---

## Additional Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Mozilla Security Guidelines: https://infosec.mozilla.org/guidelines/web_security
- Let's Encrypt: https://letsencrypt.org/
- Python Security Best Practices: https://python.readthedocs.io/en/stable/library/security_warnings.html

---
**Last Updated**: 2026-06-10  
**Version**: 2.1 (Secure & Optimized)
