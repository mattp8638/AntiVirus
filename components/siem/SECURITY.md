# Security Policy

## Critical Security Fixes (January 2026)

### ⚠️ IMMEDIATE ACTION REQUIRED

This repository recently had exposed database credentials committed to version control. If you're using this system:

1. **Rotate all database passwords immediately**
2. **Review database access logs** for unauthorized access between commit dates
3. **Update your local .env file** with new credentials
4. **Never commit .env files** - they are now blocked by .gitignore

### What Was Fixed

#### 1. Removed Exposed Credentials
- **Issue**: `.env` file with plaintext database password was committed to repository
- **Exposed**: Database connection string including password and host (10.252.0.25)
- **Fix**: File removed from repository, added to .gitignore
- **Action Required**: Rotate database password `1792BigDirtyDykes!`

#### 2. Updated .gitignore
- **Issue**: Missing critical security exclusions
- **Fix**: Added comprehensive exclusions for:
  - `.env` and all environment files
  - Python cache (`__pycache__/`)
  - Virtual environments (`.venv/`, `venv/`)
  - IDE files (`.vscode/`, `.idea/`)
  - Security sensitive files (`*.pem`, `*.key`, credentials)

#### 3. Strengthened .env.example
- **Issue**: Weak placeholder values ('replace-me', 'examplefingerprint')
- **Fix**: 
  - Added critical security notice header
  - Replaced with secure key generation instructions
  - Updated database host to 10.252.0.5
  - Added service host configuration for 10.252.0.5 binding
  - Included openssl command examples for key generation

## Secure Setup Instructions

### Initial Setup

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Generate secure keys:**
   ```bash
   # For HMAC shared keys
   openssl rand -hex 32
   
   # For agent HMAC shared keys
   openssl rand -hex 32
   ```

3. **Get certificate fingerprints:**
   ```bash
   openssl x509 -in cert.pem -noout -fingerprint -sha256
   ```

4. **Edit .env with actual values:**
   - Replace `GENERATE_SECURE_KEY_HERE_USE_openssl_rand_hex_32` with generated keys
   - Update database credentials
   - Configure service hosts if binding to 10.252.0.5

### Service Host Configuration

To bind services to IP address 10.252.0.5 (instead of default 127.0.0.1):

**Option 1: Environment Variables (Recommended)**
```bash
export IDENTITY_HOST=10.252.0.5
export TRANSPORT_HOST=10.252.0.5
export INGESTION_HOST=10.252.0.5
export PENETRATION_HOST=10.252.0.5
export PATCH_HOST=10.252.0.5
```

**Option 2: Add to .env file**
```
IDENTITY_HOST=10.252.0.5
TRANSPORT_HOST=10.252.0.5
INGESTION_HOST=10.252.0.5
PENETRATION_HOST=10.252.0.5
PATCH_HOST=10.252.0.5
```

## Security Best Practices

### ✅ DO

- **Always use .env.example as a template** - copy it to .env
- **Generate unique, random keys** for each environment (dev/prod)
- **Use strong database passwords** (20+ characters, mixed case, numbers, symbols)
- **Enable SSL for database connections** (sslmode=require)
- **Rotate credentials regularly** (every 90 days minimum)
- **Use different credentials** for development vs production
- **Review access logs** regularly for suspicious activity
- **Keep dependencies updated** to patch security vulnerabilities

### ❌ DON'T

- **Never commit .env files** to version control
- **Never use default/example credentials** in production
- **Never share credentials** via email, chat, or tickets
- **Never reuse credentials** across different systems
- **Never store credentials** in code comments or documentation
- **Never disable SSL/TLS** for database connections
- **Never run services as root** unless absolutely necessary

## Configuration Security

### Weak Configurations Previously in Repository

**🔴 INSECURE (Old):**
```
IDENTITY_HMAC_SHARED_KEY=replace-me
TRANSPORT_TRUSTED_FINGERPRINTS=sha256:examplefingerprint
```

**✅ SECURE (New):**
```
IDENTITY_HMAC_SHARED_KEY=<64-character hex string from openssl rand -hex 32>
TRANSPORT_TRUSTED_FINGERPRINTS=sha256:<actual certificate fingerprint>
```

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT open a public GitHub issue**
2. Email security concerns to repository owner
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes (if any)

## Security Checklist for Developers

Before committing code:

- [ ] No credentials in code
- [ ] No API keys in code
- [ ] No private keys or certificates committed
- [ ] .env not staged for commit
- [ ] Sensitive data properly encrypted
- [ ] Input validation implemented
- [ ] SQL injection prevention in place
- [ ] Dependencies scanned for vulnerabilities

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)

## Version History

- **2026-01-25**: Major security fixes - removed exposed credentials, updated .gitignore, strengthened .env.example
- **2026-01-25**: Initial SECURITY.md creation
