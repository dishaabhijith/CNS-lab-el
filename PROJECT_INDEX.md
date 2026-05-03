# Quantum-Resistant Authentication System - Project Index

## 📚 Documentation

### For Getting Started
- **[GETTING_STARTED.md](GETTING_STARTED.md)** ⭐ START HERE
  - Step-by-step setup instructions
  - Testing procedures
  - Troubleshooting guide
  - 5-15 minutes to get running

- **[README.md](README.md)**
  - Project overview
  - Features and architecture overview
  - Quick reference guide
  - Learning resources

- **[ARCHITECTURE.md](ARCHITECTURE.md)**
  - Detailed system design
  - Registration and login flows (diagrams)
  - Database schema
  - Security mechanisms
  - API endpoints specification

- **[POST_QUANTUM_GUIDE.md](POST_QUANTUM_GUIDE.md)**
  - Post-quantum cryptography concepts
  - Supported algorithms (SPHINCS+, XMSS, ML-DSA)
  - Installation and configuration
  - Complete code examples
  - Security properties and comparisons

- **[REPLAY_ATTACK_PREVENTION.md](REPLAY_ATTACK_PREVENTION.md)** 🆕
  - What is a replay attack?
  - Three-layer protection mechanism
  - Attack scenarios and defenses
  - Real-world attack timelines
  - Configuration and tuning
  - Complete implementation checklist

## 🏗️ Backend Files

### Application Core
- **`backend/app.py`** (440 lines)
  - Flask application factory
  - Error handlers
  - Health check endpoint
  - Application initialization

- **`backend/auth_routes.py`** (350 lines)
  - POST /auth/register - User registration
  - POST /auth/nonce - Request authentication challenge
  - POST /auth/login - Login with signed nonce
  - POST /auth/verify - Verify session token
  - POST /auth/logout - Logout
  - GET /auth/user - Get user information
  - Rate limiting and validation logic

- **`backend/models.py`** (120 lines)
  - User model (username, public key)
  - Nonce model (one-time challenge values)
  - Session model (user sessions)
  - LoginAttempt model (rate limiting tracking)

- **`backend/crypto_utils.py`** (200 lines)
  - Key pair generation (XMSS-based)
  - Message signing
  - Signature verification
  - Nonce generation
  - Helper functions for crypto operations

- **`backend/config.py`** (40 lines)
  - Configuration classes (Development, Production, Testing)
  - Session settings
  - Security parameters (nonce expiry, rate limits)

- **`backend/requirements.txt`** (6 packages)
  - Flask, Flask-CORS
  - SQLAlchemy
  - cryptography
  - python-dotenv

## 🎨 Frontend Files

### HTML
- **`frontend/index.html`** (180 lines)
  - Single-page application
  - Registration form with key generation
  - Login form with private key input
  - Dashboard (post-authentication)
  - Status message containers

### JavaScript
- **`frontend/js/crypto.js`** (180 lines)
  - QuantumCrypto class
  - generateKeyPair() - XMSS keypair generation
  - signMessage() - Sign data with private key
  - verifySignature() - Verify signatures
  - generateNonce() - Create random nonces
  - Key import/export functions
  - Browser Web Crypto API integration

- **`frontend/js/auth.js`** (400 lines)
  - AuthManager class
  - handleGenerateKeys() - UI key generation
  - handleRegister() - Registration flow
  - handleLogin() - Complete login flow
  - Session management
  - UI state management
  - Event listeners and form handling

### CSS
- **`frontend/css/style.css`** (350 lines)
  - Modern gradient design
  - Responsive layout
  - Form styling
  - Button styles
  - Dashboard layout
  - Status/error message styling
  - Mobile optimization

## 🛠️ Configuration Files

- **`.env.example`** - Environment variable template
- **`backend/.gitignore`** - Git ignore rules for backend

## 📊 File Statistics

```
Backend:
  - Python files: 5 files (~1,150 lines)
  - Dependencies: 6 packages
  - Database: SQLite (auto-created)

Frontend:
  - HTML: 1 file (~180 lines)
  - JavaScript: 2 files (~580 lines)
  - CSS: 1 file (~350 lines)
  - Total: 4 files (~1,110 lines)

Documentation:
  - 4 markdown files
  - Total: ~3,000 lines of documentation
```

## 🔄 Complete System Flow

### Registration Process
```
User visits frontend/index.html
  ↓
Click "Generate Keys"
  ↓ (frontend/js/crypto.js)
Browser generates XMSS keypair locally
  ↓
User enters username, clicks "Register"
  ↓
frontend/js/auth.js sends to backend
  ↓
backend/auth_routes.py validates and stores
  ↓ (backend/models.py)
User record created in database
  ↓
Success message shown to user
```

### Login Process
```
User enters username and private key
  ↓
Click "Login with Digital Signature"
  ↓ (frontend/js/auth.js)
Request nonce from backend/auth_routes.py
  ↓ (backend/models.py)
Nonce generated and stored in database
  ↓
frontend/js/crypto.js signs username+nonce
  ↓
Send signature to backend/auth_routes.py
  ↓ (backend/crypto_utils.py)
Backend verifies signature using public key
  ↓ (backend/models.py)
Mark nonce as used, create session
  ↓
Session token returned to frontend
  ↓
frontend/index.html shows dashboard
```

### Logout Process
```
User clicks "Logout"
  ↓ (frontend/js/auth.js)
DELETE /auth/logout with session token
  ↓
backend/auth_routes.py invalidates session
  ↓ (backend/models.py)
Session deleted from database
  ↓
frontend returns to login forms
```

## 🔐 Security Implementation

### Located in:
- **backend/crypto_utils.py** - Cryptographic operations
- **backend/auth_routes.py** - Input validation, rate limiting, nonce checking
- **backend/models.py** - Session expiration, nonce validity
- **frontend/js/crypto.js** - Client-side key generation
- **frontend/js/auth.js** - Secure session storage

### Key Security Features:
1. No password storage (public key only)
2. XMSS-based digital signatures
3. Single-use nonces with expiration
4. Rate limiting on login attempts
5. Session token expiration
6. CORS protection
7. Input validation on all endpoints
8. Secure cookie flags (production)

## 🚀 How to Run

### Quick Start (5 minutes):

```bash
# Terminal 1: Backend
cd backend
python -m venv venv
venv\Scripts\activate  # Windows: or source venv/bin/activate
pip install -r requirements.txt
python app.py

# Terminal 2: Frontend
# (in project root, not backend)
python -m http.server 8000
# or: npx http-server -p 8000

# Browser: http://localhost:8000/frontend/index.html
```

See **GETTING_STARTED.md** for detailed instructions.

## 📖 Learning Path

### Beginner (1-2 hours)
1. Read GETTING_STARTED.md
2. Run the application
3. Test registration and login
4. Read ARCHITECTURE.md sections 1-5

### Intermediate (2-4 hours)
1. Read entire ARCHITECTURE.md
2. Explore backend code (app.py → auth_routes.py → models.py)
3. Explore frontend code (index.html → auth.js → crypto.js)
4. Understand cryptographic operations in crypto_utils.py

### Advanced (4+ hours)
1. Modify the system (add features)
2. Integrate with official XMSS library
3. Add production security features
4. Create comprehensive test suite
5. Deploy to production environment

## 🔍 Code Quality Notes

### Documentation
- Every function has docstrings
- Inline comments explain complex logic
- README and ARCHITECTURE provide overview

### Modularity
- Crypto operations separated (crypto_utils.py)
- Database models separated (models.py)
- Routes organized in blueprints (auth_routes.py)
- Frontend logic organized in classes (QuantumCrypto, AuthManager)

### Error Handling
- Try-catch blocks around critical operations
- User-friendly error messages
- Server logs detailed errors
- Graceful fallbacks

### Security
- Input validation on all endpoints
- Rate limiting
- Nonce-based replay attack prevention
- No sensitive data in logs
- Secure session management

## 📝 Educational Value

This project teaches:

### Cryptography
- Post-quantum algorithms (XMSS)
- Digital signatures
- Key generation and storage
- Hash functions

### Web Security
- Authentication flows
- Session management
- CORS and cross-origin requests
- Input validation
- Rate limiting
- Secure HTTP headers

### Software Architecture
- Client-server architecture
- API design (REST principles)
- Database design
- Configuration management
- Error handling

### Web Development
- Flask framework
- SQLAlchemy ORM
- Frontend JavaScript
- Async/await patterns
- Browser APIs (Web Crypto, localStorage)

## 🎯 Next Steps

1. **Complete GETTING_STARTED.md** to get the system running
2. **Test all flows** to understand the system
3. **Read the code** to see how it's implemented
4. **Modify and extend** to add new features
5. **Deploy** to a production environment

---

## 📊 Project Metadata

- **Type**: Educational cryptography project
- **Level**: Advanced undergraduate / graduate
- **Time to implement**: 20-40 hours (designed)
- **Time to understand**: 2-4 hours
- **Time to modify**: 2-8 hours per enhancement
- **Dependencies**: Python 3.8+, Flask, modern browser
- **Database**: SQLite (development), PostgreSQL (production)
- **Authentication**: Post-quantum digital signatures (XMSS)

---

**Start with [GETTING_STARTED.md](GETTING_STARTED.md) →** 🚀
