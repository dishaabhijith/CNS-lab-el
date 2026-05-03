# Quantum-Resistant Authentication System Architecture

## System Overview
A post-quantum cryptographic authentication system using digital signatures (XMSS) instead of traditional passwords. Uses nonce-based challenge-response to prevent replay attacks.

## Key Components

### 1. Cryptographic Foundation
**Algorithm: XMSS (eXtendable Merkle Signature Scheme)**
- Hash-based, post-quantum secure
- Fast signature verification
- Stateless variant available
- Suitable for student projects

**Alternative: SPHINCS+**
- Stateless (simpler implementation)
- Larger signatures but no state management needed

### 2. Authentication Flow

#### Registration Flow
```
Client                              Server
  |                                   |
  |-- Generate key pair (XMSS) ----->|
  |                                   |
  |-- Send public key + username ---->|
  |                                   |-- Store public key in DB
  |                                   |-- Return success/error
  |<-- Registration confirmed --------|
```

**Server Actions:**
1. Validate username uniqueness
2. Store public key (not password)
3. Create user record with public key

#### Login/Authentication Flow
```
Client                              Server
  |                                   |
  |-- Request nonce (username) ----->|
  |                                   |-- Generate random nonce
  |                                   |-- Store nonce (short TTL)
  |<-- Return nonce -------------------|
  |                                   |
  |-- Sign(username + nonce) -------->|
  |-- Send username + signature ----->|
  |                                   |-- Retrieve stored nonce
  |                                   |-- Verify signature
  |                                   |-- Delete used nonce
  |                                   |-- Create session
  |<-- Auth token/session ------------|
```

**Security Properties:**
- Nonce prevents replay attacks (one-time use)
- Signature proves possession of private key
- No password transmission
- Resistant to quantum attacks

### 3. Database Schema

**Users Table:**
```
id (PK)
username (UNIQUE)
public_key (stored as hex/base64)
created_at
```

**Nonces Table:**
```
id (PK)
user_id (FK)
nonce (random 32 bytes, hex encoded)
created_at
expires_at (TTL: 5 minutes)
used (boolean)
```

**Sessions Table:**
```
id (PK)
user_id (FK)
session_token
created_at
expires_at
```

### 4. Key Storage

**Client-side:**
- Private key stored locally (development: JSON file, production: encrypted)
- Public key known by server

**Server-side:**
- Public keys in database
- Nonces temporary (Redis or DB with TTL)
- No password storage

### 5. API Endpoints

**POST /auth/register**
- Request: `{username, public_key}`
- Response: `{success, user_id, message}`

**POST /auth/nonce**
- Request: `{username}`
- Response: `{nonce, nonce_id}`

**POST /auth/login**
- Request: `{username, signature, nonce}`
- Response: `{session_token, expires_at}` or error

**POST /auth/verify**
- Request: `{session_token}`
- Response: `{valid, user_id}` or error

**POST /auth/logout**
- Request: `{session_token}`
- Response: `{success}`

### 6. Security Mechanisms

| Threat | Mechanism | Implementation |
|--------|-----------|-----------------|
| Password breach | No passwords stored | Public key cryptography |
| Replay attacks | Single-use nonce | Nonce invalidation after use |
| Quantum attacks | Post-quantum algorithm | XMSS hash-based signatures |
| Man-in-the-middle | HTTPS (production) | SSL/TLS encryption |
| Private key loss | Key recovery phrase | Optional: Mnemonic backup |
| Session hijacking | Secure tokens | Random tokens + expiration |

### 7. Implementation Technologies

**Backend:**
- Flask (Python web framework)
- cryptography/pqcrypto libraries for XMSS
- SQLAlchemy (ORM)
- SQLite (development) / PostgreSQL (production)

**Frontend:**
- HTML/JavaScript
- Web Crypto API (key generation)
- Fetch API (HTTP requests)

**Security Practices:**
- HTTPS only (production)
- Secure session cookies (httpOnly, secure flags)
- Input validation on all endpoints
- Rate limiting on auth endpoints
- CORS configuration

### 8. Data Flow Diagram

```
┌─────────────────┐
│   Client App    │
│  (HTML/JS)      │
└────────┬────────┘
         │
    [HTTPS/HTTP]
         │
    ┌────▼─────────────┐
    │  Flask Backend   │
    │   - Auth routes  │
    │   - Key verify   │
    └────┬─────────────┘
         │
    ┌────▼──────────────┐
    │  Database         │
    │  - Users table    │
    │  - Nonces table   │
    │  - Sessions table │
    └───────────────────┘
```

### 9. Project Structure

```
quantum-auth-system/
├── backend/
│   ├── app.py              # Main Flask app
│   ├── config.py           # Configuration
│   ├── auth_routes.py      # Authentication endpoints
│   ├── models.py           # Database models
│   ├── crypto_utils.py     # XMSS operations
│   ├── database.py         # DB initialization
│   └── requirements.txt    # Dependencies
├── frontend/
│   ├── index.html          # Registration/login UI
│   ├── dashboard.html      # Post-auth page
│   ├── js/
│   │   ├── crypto.js       # Client-side crypto (key generation)
│   │   └── auth.js         # Auth flow logic
│   └── css/
│       └── style.css       # Styling
├── ARCHITECTURE.md         # This file
└── README.md               # Setup instructions
```

### 10. Simplified Flow for Students

**To make it understandable:**
1. Registration: Generate keypair → Send public key to server
2. Login: Get nonce → Sign it → Send signature → Server verifies
3. No passwords needed - digital signatures prove you own the private key

**Why Quantum-Resistant?**
- XMSS is based on hash functions
- Even quantum computers can't break hash-based signatures efficiently
- Traditional RSA/ECDSA would be broken by quantum computers

---

## Next Steps
1. Set up Flask project structure
2. Implement database models
3. Create crypto utility functions for XMSS
4. Build API endpoints
5. Create HTML/JS frontend
6. Test authentication flows
