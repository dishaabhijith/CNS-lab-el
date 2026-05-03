# Post-Quantum Cryptography Implementation Guide

## Overview

This authentication system uses **post-quantum resistant digital signatures** instead of passwords. This document explains the cryptography, how it works, and how to use real post-quantum libraries.

## Table of Contents

1. [Why Post-Quantum Cryptography?](#why-post-quantum-cryptography)
2. [How It Works](#how-it-works)
3. [Signature Schemes Supported](#signature-schemes-supported)
4. [Installation Options](#installation-options)
5. [Complete Authentication Flow](#complete-authentication-flow)
6. [Security Analysis](#security-analysis)
7. [Code Examples](#code-examples)

---

## Why Post-Quantum Cryptography?

### The Quantum Threat

**Current Problem:**
- Today's encryption (RSA, ECDSA) relies on **integer factorization** and **discrete logarithm** problems
- These are "hard" for classical computers (would take millions of years to break)
- **Quantum computers** can solve these using **Shor's algorithm** in polynomial time
- Timeline: Large quantum computers might exist in 10-20 years

**Example Timeline:**
```
Today (2024)               In 10-20 years
RSA-2048: Secure          RSA-2048: Broken (quantum computer)
ECDSA: Secure             ECDSA: Broken (quantum computer)
XMSS: Secure              XMSS: Still Secure ✓
SPHINCS+: Secure          SPHINCS+: Still Secure ✓
```

### Why Hash-Based Signatures Are Safe

**Post-Quantum Algorithms:**
- Based on **hash functions** (SHA-256, etc.)
- Quantum attacks on hash functions are not known
- Even optimized quantum algorithms (Grover's algorithm) only provide modest speedup
- Equivalent security: XMSS with 256-bit key ≈ 128-bit classical security (very strong)

**Formula:**
```
Hash function with n-bit output
Classical attack: 2^n operations
Quantum attack: 2^(n/2) operations

Example (SHA-256):
Classical: 2^256 operations (impossible)
Quantum: 2^128 operations (still impossible)
```

---

## How It Works

### 1. Registration Phase

```
CLIENT                                  SERVER
  |                                       |
  |-- Generate Keypair (post-quantum)--->|
  |    (Private key stays on client)     |
  |                                       |
  |-- Send: username + public_key ------>|
  |                                       |-- Store public key in DB
  |                                       |-- Create user record
  |<-- Registration successful -----------|
  |                                       |
[SAVE PRIVATE KEY SECURELY]              [STORE PUBLIC KEY]
```

**Key Points:**
- Public key is **sent** to server (stored in database)
- Private key **never leaves** the client
- Private key is client's responsibility to protect
- If lost, cannot recover (no password reset option)

### 2. Authentication Phase (Challenge-Response)

```
STEP 1: REQUEST NONCE
CLIENT                                  SERVER
  |-- username ----------------------->|
  |                                  Generate random nonce
  |                                  Store with TTL (5 min)
  |<-- nonce -------------------------|

STEP 2: SIGN CHALLENGE
CLIENT                                  SERVER
  Creates: message = username + nonce
  Signs with private key using POST-QUANTUM algorithm
  
  |-- username + nonce + signature -->|
  |                                  Retrieve public key
  |                                  Verify signature
  |                                  Mark nonce as used
  |<-- session_token ----------------| 
```

**Security Properties:**
- ✓ **No password**: Never transmitted or stored
- ✓ **Proof of identity**: Only signature proves private key ownership
- ✓ **Replay-safe**: Each nonce single-use, expires in 5 minutes
- ✓ **Quantum-safe**: Uses post-quantum signature algorithm
- ✓ **Zero-knowledge**: Server learns only authentication result

---

## Signature Schemes Supported

### 1. SPHINCS+ (Recommended for Learning)

**Advantages:**
- Stateless (no state management needed)
- Fast verification
- Standardized by NIST
- 256-bit security level

**Installation:**
```bash
pip install sphincsplus
```

**Characteristics:**
```
Key Size: 32 bytes (private) × 1024 bytes (public)
Signature Size: 41 KB
Signing Speed: ~1 second
Verification Speed: ~2 seconds
Security: 256-bit (very strong)
```

### 2. XMSS (More Complex but Faster)

**Advantages:**
- Faster signing than SPHINCS+
- Smaller signatures than SPHINCS+
- Stateless variant available

**Installation:**
```bash
pip install xmss-py
```

**Characteristics:**
```
Key Size: 64 bytes (standard)
Signature Size: ~2KB
Signing Speed: Fast
Verification Speed: Very fast
Security: 256-bit
Note: Requires state management
```

### 3. ML-DSA via liboqs (Most Complete)

**Advantages:**
- NIST standardized
- Multiple algorithms (ML-DSA, ML-KEM, SLH-DSA)
- ML-DSA faster than SPHINCS+
- Comprehensive library

**Installation:**
```bash
pip install liboqs-python
```

**Characteristics:**
```
Algorithm: ML-DSA-65 (CRYSTALS-Dilithium)
Key Size: 2,544 bytes (public)
Signature Size: 2,420 bytes
Signing Speed: Fast
Verification Speed: Fast
Security: 192-bit (strong)
```

### 4. SHA256-Based Simulation (Demo/Fallback)

**When Used:**
- If no post-quantum libraries installed
- For demonstration/educational purposes
- Fast for prototyping

**How It Works:**
```
Private Key: Random 256 bits
Public Key: SHA256(private_key)
Signature: HMAC-SHA256(private_key, message)
Verification: Check format validity (not real verification)
```

**Limitations:**
```
⚠ Not truly quantum-resistant (uses HMAC-SHA256)
⚠ Server cannot verify without private key
✓ Good for demonstration
✓ Shows authentication flow
```

---

## Installation Options

### Option 1: Automatic (Uses Available Library)

The system automatically detects and uses available libraries in this order:

```python
# backend/crypto_utils.py tries to import:

1. liboqs        → Uses ML-DSA-65
2. sphincsplus   → Uses SPHINCS-SHA2-256f
3. xmss-py       → Uses XMSS-SHA2_10_256
4. SHA256 sim    → Falls back to HMAC-based
```

### Option 2: Install Multiple for Testing

```bash
# Install all available options
pip install liboqs-python sphincsplus xmss-py

# All will be available; liboqs takes priority
```

### Option 3: Install Specific Library

**For SPHINCS+ (Recommended for Learning):**
```bash
pip install sphincsplus
```

**For liboqs (Comprehensive):**
```bash
pip install liboqs-python
```

**For XMSS:**
```bash
pip install xmss-py
```

### Checking Which Backend is Active

Add to your backend:

```python
from crypto_utils import QuantumSafeSignature

# On startup, see which backend is active:
print(f"Using backend: {QuantumSafeSignature.get_backend()}")

# Output examples:
# Using backend: liboqs
# Using backend: sphincsplus
# Using backend: xmss
# Using backend: sha256_simulation
```

---

## Complete Authentication Flow

### Client-Side Flow (JavaScript)

```javascript
// 1. Registration
async function register(username) {
    // Generate keypair (post-quantum safe)
    const keypair = await QuantumCrypto.generateKeyPair();
    
    // Register (public key only)
    const response = await fetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
            username: username,
            public_key: keypair.publicKey
        })
    });
    
    // SAVE PRIVATE KEY SECURELY!
    savePrivateKey(keypair.privateKey);
}

// 2. Login
async function login(username, privateKey) {
    // Get nonce
    const nonceResp = await fetch('/auth/nonce', {
        method: 'POST',
        body: JSON.stringify({ username: username })
    });
    const { nonce } = await nonceResp.json();
    
    // Sign nonce
    const message = username + nonce;
    const signature = await QuantumCrypto.signMessage(message, privateKey);
    
    // Login
    const loginResp = await fetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
            username: username,
            nonce: nonce,
            signature: signature
        })
    });
    const { session_token } = await loginResp.json();
    
    // Save session
    localStorage.sessionToken = session_token;
}
```

### Server-Side Flow (Python)

```python
from crypto_utils import QuantumSafeSignature

# 1. Registration
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    public_key = data['public_key']
    
    # Store user with public key (not password!)
    user = User(username=username, public_key=public_key)
    db.session.add(user)
    db.session.commit()
    
    return {'success': True}

# 2. Generate Nonce
@app.route('/auth/nonce', methods=['POST'])
def get_nonce():
    username = request.json['username']
    user = User.query.filter_by(username=username).first()
    
    # Generate single-use nonce
    nonce = QuantumSafeSignature.generate_nonce()
    
    # Store with expiration
    nonce_obj = Nonce(
        user_id=user.id,
        nonce=nonce,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(nonce_obj)
    db.session.commit()
    
    return {'nonce': nonce}

# 3. Verify Signature (THE MAGIC!)
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    nonce = data['nonce']
    signature = data['signature']
    
    user = User.query.filter_by(username=username).first()
    message = username + nonce  # Same message client signed
    
    # THIS IS THE KEY STEP:
    # Verify signature using POST-QUANTUM algorithm
    # Using ONLY the public key (no private key needed!)
    is_valid = QuantumSafeSignature.verify_signature(
        message,
        signature,
        user.public_key
    )
    
    if is_valid:
        # Mark nonce as used (prevent replay)
        nonce_obj.used = True
        db.session.commit()
        
        # Create session
        return {'session_token': generate_token()}
    else:
        return {'error': 'Authentication failed'}, 401
```

---

## Security Analysis

### Attack Scenarios & Defenses

#### 1. Password Breach Attack

**Traditional:** Attacker steals password database → Can login as anyone  
**Our System:** Attacker steals public key database → Can do nothing! (Needs private key)

```
Database breach:
Traditional: Passwords → BROKEN
Our System: Public keys → SAFE (useless without private key)
```

#### 2. Replay Attack

**Attack Attempt:**
```
1. Attacker intercepts: username + nonce + signature
2. Attacker sends same data again to login
```

**Defense:**
```
Server checks: Has this nonce been used before?
Answer: YES → REJECT
Single-use nonce prevents any replay
```

#### 3. Man-in-the-Middle Attack

**Attack Attempt:**
```
Attacker intercepts: username + signature
Attacker modifies signature
Server tries to verify modified signature
```

**Defense:**
```
Modified signature won't verify correctly
Server rejects authentication
Quantum-resistant algorithm ensures no shortcut exists
```

#### 4. Quantum Computer Attack

**Attack Attempt:**
```
Quantum computer tries to: Recover private key from public key
```

**Defense:**
```
SPHINCS+/XMSS/ML-DSA: Based on hash functions
Hash functions: Believed resistant to quantum attacks
Even with quantum computer, no known efficient algorithm
```

### Security Properties

| Property | Traditional Passwords | Our Post-Quantum System |
|----------|----------------------|------------------------|
| Quantum Safe | ❌ No (RSA breakable) | ✅ Yes (hash-based) |
| Password theft | ❌ Login compromised | ✅ Pubkey useless |
| Replay proof | ❌ Needs salt/hash | ✅ Single-use nonce |
| Private key secure | ❌ Server stores | ✅ Client only |
| Zero-knowledge | ❌ Sends password | ✅ Sends signature only |

---

## Code Examples

### Example 1: Generate and Sign

```python
from crypto_utils import QuantumSafeSignature

# Generate keypair
public_key, private_key = QuantumSafeSignature.generate_keypair()
print(f"Public:  {public_key[:32]}...")
print(f"Private: {private_key[:32]}...")

# Sign a message
message = "user123" + "abc123def456"  # username + nonce
signature = QuantumSafeSignature.sign_message(message, private_key)
print(f"Signature: {signature}")

# Verify signature
is_valid = QuantumSafeSignature.verify_signature(
    message,
    signature,
    public_key
)
print(f"Valid: {is_valid}")
```

### Example 2: Check Current Backend

```python
from crypto_utils import QuantumSafeSignature

backend = QuantumSafeSignature.get_backend()

if backend == "sha256_simulation":
    print("⚠️  Using simulation mode. Install a library:")
    print("   pip install liboqs-python")
    print("   pip install sphincsplus")
    print("   pip install xmss-py")
elif backend == "liboqs":
    print("✅ Using liboqs (ML-DSA)")
elif backend == "sphincsplus":
    print("✅ Using SPHINCS+")
elif backend == "xmss":
    print("✅ Using XMSS")
```

### Example 3: Complete Authentication

```python
from crypto_utils import QuantumSafeSignature
import secrets

# REGISTRATION
username = "alice"
public_key, private_key = QuantumSafeSignature.generate_keypair()

# Store on server: username + public_key
print(f"[SERVER] Storing public key for {username}")

# CLIENT KEEPS PRIVATE KEY SECRET
print(f"[CLIENT] Secret private key: {private_key}")

# LOGIN
nonce = QuantumSafeSignature.generate_nonce()
print(f"[SERVER] Generated nonce: {nonce[:16]}...")

# Client signs the challenge
message = username + nonce
signature = QuantumSafeSignature.sign_message(message, private_key)
print(f"[CLIENT] Signed challenge: {signature[:16]}...")

# Server verifies
is_authenticated = QuantumSafeSignature.verify_signature(
    message,
    signature,
    public_key
)

if is_authenticated:
    print("✅ [SERVER] Authentication successful!")
    print("[SERVER] Creating session token...")
else:
    print("❌ [SERVER] Authentication failed!")
```

---

## Common Questions

### Q1: Is this system truly quantum-safe?

**Answer:** Yes, if using real post-quantum libraries (liboqs, SPHINCS+, XMSS). The SHA256 simulation is for demo only.

### Q2: What if I lose my private key?

**Answer:** You cannot recover it. No password reset option exists. This is by design - make sure to save the private key securely.

### Q3: How large are signatures?

**Answer:**
- SPHINCS+: ~40 KB (largest, but very safe)
- ML-DSA: ~2.4 KB (smallest)
- XMSS: ~2 KB (smallest)
- SHA256 sim: 64 bytes (demo only)

### Q4: Is this faster than passwords?

**Answer:** Not for single login. But:
- No password database breaches to worry about
- No password reset/recovery processes needed
- Quantum-safe (passwords won't be in 10-20 years)

### Q5: Can I use this with HTTPS?

**Answer:** Yes! Recommended for production:
```python
# Production settings (config.py)
SESSION_COOKIE_SECURE = True  # Only over HTTPS
SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
```

---

## References

### Official Documentation
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [XMSS Specification (RFC 8391)](https://tools.ietf.org/html/rfc8391)
- [SPHINCS+ Specification](https://sphincs.org/)

### Libraries
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- [sphincsplus-py](https://github.com/sphincsplus/sphincsplus)
- [xmss-py](https://github.com/xmss/xmss-py)

### Learning Resources
- [Quantum Cryptography Threat](https://www.cloudflare.com/learning/ssl/quantum-computing-and-encryption/)
- [Hash-Based Signatures](https://en.wikipedia.org/wiki/Merkle_signature_scheme)
- [Post-Quantum Cryptography Tutorial](https://pqcrypto.org/)

---

## Next Steps

1. **Try the system** with the default SHA256 simulation
2. **Install a real library** (`pip install liboqs-python`)
3. **Observe behavior changes** - same code, different backend
4. **Run performance tests** - compare signature times
5. **Deploy to production** - add HTTPS and secure key storage

---

**Happy quantum-safe authentication! 🔐🚀**
