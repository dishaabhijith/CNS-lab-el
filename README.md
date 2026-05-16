# Quantum-Resistant Authentication System

A modern authentication system using **post-quantum cryptography** instead of traditional passwords. This project demonstrates how to implement secure, quantum-safe authentication using digital signatures.

## 🔐 Key Features

- ✅ **Post-Quantum Security**: Uses hash-based signatures (SPHINCS+, XMSS, ML-DSA) - resistant to quantum computer attacks
- ✅ **No Passwords**: Authentication via digital signatures instead of passwords
- ✅ **Replay Attack Prevention**: Nonce-based challenge-response mechanism (one-time use)
- ✅ **Public Key Storage**: Server stores only public keys, never private keys
- ✅ **Session Management**: Secure token-based sessions with expiration
- ✅ **Multiple Crypto Backends**: Auto-detects liboqs, SPHINCS+, XMSS, with a browser-ready WOTS-SHA256 fallback
- ✅ **Rate Limiting**: Protection against brute-force attacks
- ✅ **Educational**: Easy to understand implementation suitable for student projects

## 🏗️ Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design, flows, and security mechanisms.

### Quick Overview

```
Registration:
  Client → Generate keypair → Send public key → Server stores it

Login:
  Client → Request nonce → Sign(username + nonce) → Server verifies → Session issued
```

## 🔐 Post-Quantum Cryptography

This system uses **post-quantum resistant digital signatures** instead of passwords or traditional cryptography:

### Why Post-Quantum?
- **Threat**: Quantum computers (RSA/ECDSA can be broken by quantum computers using Shor's algorithm)
- **Solution**: Hash-based signatures (SPHINCS+, XMSS, ML-DSA) are believed quantum-resistant
- **Timeline**: Large quantum computers may exist in 10-20 years
- **Protection**: This system is quantum-safe now and for the future

### Supported Algorithms
| Algorithm | Library | Key Type | Status |
|-----------|---------|----------|--------|
| SPHINCS+ | sphincsplus | Hash-based | ✅ Recommended |
| XMSS | xmss-py | Hash-based | ✅ Fast |
| ML-DSA | liboqs | Lattice-based | ✅ NIST Standard |
| WOTS-SHA256 | native Web Crypto/Python | Hash-based demo | ✅ Browser-ready |

### Install Real Post-Quantum (Optional)
```bash
# Auto-detects available libraries in this order:
pip install liboqs-python      # NIST-standardized
pip install sphincsplus         # Hash-based
pip install xmss-py             # Memory-efficient

# System reports installed PQC libraries and uses WOTS-SHA256 in the browser UI
```

**For detailed cryptography explanation, see [POST_QUANTUM_GUIDE.md](POST_QUANTUM_GUIDE.md)**

**For replay attack prevention details, see [REPLAY_ATTACK_PREVENTION.md](REPLAY_ATTACK_PREVENTION.md)**

**For deployment hardening status, see [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)**

**For demo flow and feature explanation, see [DEMO_AND_FEATURES.md](DEMO_AND_FEATURES.md)**

## 📋 Project Structure

```
quantum-auth-system/
├── backend/                 # Python Flask backend
│   ├── app.py              # Main Flask application
│   ├── auth_routes.py      # Authentication endpoints
│   ├── models.py           # Database models
│   ├── crypto_utils.py     # Cryptographic functions
│   ├── config.py           # Configuration management
│   └── requirements.txt    # Python dependencies
├── frontend/               # Vite + React frontend
│   ├── index.html          # Single-page application
│   ├── js/
│   │   ├── crypto.js       # Client-side key generation & signing
│   │   └── auth.js         # Authentication flow logic
│   └── css/
│       └── style.css       # Styling
├── ARCHITECTURE.md         # Detailed system design
└── README.md               # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Safari, Edge)
- Node.js (optional, for serving frontend locally)

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Flask server
python app.py
```

The backend will start at `http://localhost:5000`

### 2. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run Vite dev server
npm run dev
```

Visit: `http://127.0.0.1:5173`

## 📖 Usage Guide

### Registration

1. **Generate Keys**: Click "Generate keys"
   - Creates a WOTS-SHA256 hash-based key bundle locally in your browser
   - Public key: Sent to server (stored in database)
   - Private key: Keep safe! (never sent to server)

2. **Save Private Key**: Download or copy your private key
   - ⚠️ **CRITICAL**: You need this to login!
   - Store securely (password manager or encrypted file)

3. **Register**: Click "Register public key"
   - Username and public key sent to server
   - Account is created

### Login

1. **Enter Credentials**: Username and private key
   - Private key never sent directly to server
   - Only used to sign the authentication challenge

2. **Authentication Flow**:
   - Request nonce from server (unique, one-time value)
   - Sign `username + nonce` with private key locally
   - Send username + signature to server
   - Server verifies signature using stored public key
   - If valid, session is created

3. **Access Dashboard**: View session, runtime, nonce, signature, and API activity panels

### Logout

Click "Logout" to end the session and return to login screen.

## 🔑 Understanding the Cryptography

### Why Post-Quantum?

Traditional encryption (RSA, ECDSA) could be broken by quantum computers using Shor's algorithm. XMSS is based on hash functions and is believed to be quantum-resistant.

### Key Generation (XMSS)

1. Generate random private key (256 bits)
2. Derive public key by hashing the private key
3. In production XMSS: build a Merkle tree with multiple hash layers

### Signature Process

1. Client receives nonce from server
2. Create message: `username + nonce`
3. Sign message with a one-time WOTS-SHA256 private-key slot
4. Send signature to server

### Verification Process

1. Server retrieves stored public key for user
2. Server received: username + nonce + signature
3. Verify signature matches the message using the public key
4. Check nonce hasn't been used before (stored in database)
5. If all valid: create session

### Replay Attack Prevention

- Each nonce is unique and single-use
- Nonce expires after 5 minutes
- Server marks nonce as "used" after successful login
- Same nonce cannot be reused

##  API Reference

### Endpoints

#### POST /auth/register
Register new user with public key
```json
{
  "username": "alice",
  "public_key": "abc123...def456"
}
```

#### POST /auth/nonce
Request authentication challenge
```json
{
  "username": "alice"
}
```

#### POST /auth/login
Authenticate with signed nonce
```json
{
  "username": "alice",
  "nonce": "xyz789...",
  "signature": "sig123..."
}
```

#### POST /auth/verify
Verify session token
```
Headers: Authorization: Bearer <token>
```

#### POST /auth/logout
Invalidate session
```
Headers: Authorization: Bearer <token>
```

#### GET /auth/user
Get authenticated user info
```
Headers: Authorization: Bearer <token>
```

## 🧪 Testing

### Manual Testing

1. **Test Registration**:
   - Create account with new username
   - Save private key locally
   - Try registering same username again (should fail)

2. **Test Login**:
   - Login with correct private key (should succeed)
   - Try login with wrong private key (should fail)
   - Login again with same key (should work - different nonce)

3. **Test Session**:
   - Logout and login again
   - Session token should be different each time

### API Testing with cURL

```bash
# Register
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","public_key":"abc123...def456"}'

# Get nonce
curl -X POST http://localhost:5000/auth/nonce \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}'

# Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","nonce":"xyz...","signature":"sig..."}'
```

## 📚 Learning Resources

### Quantum Cryptography
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [XMSS Specification (RFC 8391)](https://tools.ietf.org/html/rfc8391)
- [Quantum Computing Threat to Cryptography](https://www.cloudflare.com/learning/ssl/quantum-computing-and-encryption/)

### Flask & Web Security
- [Flask Official Documentation](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Session Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

### Digital Signatures
- [Digital Signatures Explained](https://en.wikipedia.org/wiki/Digital_signature)
- [Hash-Based Signatures](https://csrc.nist.gov/projects/hash-based-digital-signature-standard)

## 🔄 Extending the System

### Production Enhancements

1. **Use Official XMSS Library**:
   ```bash
   pip install xmss-py
   # or
   pip install sphincsplus
   ```

2. **Add HTTPS/TLS**:
   - Use self-signed certs in development
   - Real certs from CA in production

3. **Database**:
   - Replace SQLite with PostgreSQL for production
   - Add connection pooling

4. **Key Recovery**:
   - Implement mnemonic phrase backup
   - Hardware security modules (HSM) for private keys

5. **Monitoring**:
   - Add logging and alerting
   - Monitor failed login attempts
   - Track session activity

## ⚙️ Configuration

Edit `backend/config.py` to customize:

```python
# Session lifetime (default 24 hours)
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

# Nonce expiration (default 5 minutes)
NONCE_EXPIRY = timedelta(minutes=5)

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
```

## 🐛 Troubleshooting

### CORS Errors
- Ensure backend is running on `localhost:5000`
- Frontend should be on `localhost:8000` or served via file://
- Check browser console for specific error messages

### Key Generation Fails
- Browser must support Web Crypto API (all modern browsers)
- Check browser privacy settings aren't blocking crypto operations

### Login Fails
- Ensure private key format is correct (64 hex characters)
- Nonce may have expired (max 5 minutes)
- Check backend logs for detailed errors

### Database Errors
- Delete `quantum_auth.db` in backend directory to reset
- Ensure database file is in backend working directory

## 📝 Notes for Students

This is an **educational implementation** demonstrating quantum-resistant authentication concepts. For production systems:

1. Use official XMSS/SPHINCS+ implementations
2. Add HTTPS/TLS encryption
3. Implement proper key management
4. Add comprehensive logging and monitoring
5. Follow security best practices (input validation, output encoding, etc.)
6. Conduct security audits and penetration testing

## 🤝 Contributing

This is a student project. Feel free to:
- Add features (password reset, two-factor auth, etc.)
- Improve security (add rate limiting improvements, etc.)
- Create tests
- Add documentation
- Fix bugs

## 📄 License

Educational use. Feel free to use and modify for learning.

## 🎓 Project Overview

This system demonstrates:
- Post-quantum cryptography concepts
- Digital signature authentication
- Challenge-response protocols
- Session management
- Web security best practices
- Flask web development
- Client-server architecture

Perfect for: Cybersecurity courses, cryptography labs, web security training, or as a portfolio project.

---

**Happy learning! 🚀**
