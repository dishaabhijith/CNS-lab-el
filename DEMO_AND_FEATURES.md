# Quantum-Resistant Authentication Demo Guide

This document explains what was added to the project, what the frontend shows, and how to present the system as more than a normal login page.

## What This Project Demonstrates

This is a passwordless authentication prototype based on challenge-response digital signatures.

Instead of storing or checking passwords, the system works like this:

1. The browser generates a public/private key bundle.
2. The backend stores only the public key.
3. During login, the backend sends a fresh nonce.
4. The browser signs `username + nonce` with the private key.
5. The backend verifies the signature using the stored public key.
6. The nonce is marked used so the same login proof cannot be replayed.

The important security idea is that the server never stores passwords or private keys.

## Major Additions

### 1. Vite + React Frontend

The old static frontend was replaced with a Vite React app.

Important files:

- `frontend/package.json`
- `frontend/vite.config.js`
- `frontend/src/App.jsx`
- `frontend/src/styles.css`
- `frontend/src/lib/quantumCrypto.js`

Run it with:

```powershell
cd D:\CNS-lab-el\frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

### 2. New Frontend Console

The new frontend is a security console with these sections:

#### Register

Used to:

- Enter username.
- Generate an ML-DSA-65 post-quantum keypair.
- View public key JSON.
- View private key JSON.
- Download or copy the private key.
- Register only the public key with the backend.

#### Login

Used to:

- Paste or load private key.
- Request a nonce from the backend.
- Sign the nonce locally in the browser.
- Send the signature to the backend.
- Receive a session after successful verification.

#### Session Dashboard

Shows:

- Authenticated username.
- User ID.
- Session expiry.
- Signature algorithm.
- Remaining one-time signature slots.
- Hidden session token status.
- `/auth/user` response.

#### Runtime Panel

Shows:

- Backend status.
- Best installed backend PQC algorithm.
- Browser default algorithm.
- Nonce expiry time.
- Available or missing optional PQC algorithms.

Example:

```text
Backend: Online
Backend PQC: ML-DSA-65
Nonce TTL: 5m
Browser Default: ML-DSA-65
```

#### Nonce and Signature Panel

Shows:

- Latest nonce.
- Nonce ID.
- Assigned one-time key slot.
- Remaining slots.
- Loaded private key slots.
- Latest signature summary.

#### API Activity Panel

Shows recent API calls:

- `/health`
- `/auth/algorithms`
- `/auth/register`
- `/auth/nonce`
- `/auth/login`
- `/auth/verify`
- `/auth/user`
- `/auth/logout`

This helps demonstrate the actual protocol flow.

## Backend Hardening Added

### Production Configuration Checks

The backend now refuses unsafe production settings:

- Default development `SECRET_KEY` is blocked in production.
- Wildcard CORS is blocked in production.
- SQLite is blocked in production.
- Secure cookies are required in production mode.

Files:

- `backend/config.py`
- `backend/app.py`

### CORS Allowlist

The backend now uses explicit frontend origins instead of allowing every origin.

Development origins include:

```text
http://localhost:5173
http://127.0.0.1:5173
http://localhost:4173
http://127.0.0.1:4173
```

### Security Headers

API responses now include safer headers such as:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cache-Control`
- `Content-Security-Policy`
- Optional HSTS

### Safer Request Validation

The backend now:

- Requires JSON object request bodies.
- Rejects oversized public keys.
- Rejects oversized signatures.
- Validates nonce format before database lookup.
- Validates usernames consistently.

### Generic Nonce Failure

`/auth/nonce` no longer reveals whether a username exists.

Instead of:

```text
User not found
```

it returns:

```text
Authentication challenge unavailable
```

This reduces user enumeration risk.

### Replay Protection Improvements

Nonce consumption is now stricter.

When a nonce is used, the backend conditionally marks it used before signature verification completes. This prevents reuse of the same nonce/signature pair.

If a wrong signature is submitted for a valid nonce, that nonce is consumed. The attacker cannot keep retrying signatures against the same challenge.

### Session Token Storage

Session tokens are HMAC-hashed before being stored in the database.

That means the database does not store raw bearer tokens.

### Frontend Session Storage

The frontend now stores session tokens in `sessionStorage` instead of `localStorage`.

This means the session is tab-scoped and is cleared more naturally when the browsing session ends.

The dashboard also hides the token instead of displaying token bytes.

## Tests Added

New tests are in:

```text
tests/test_auth_security.py
```

They verify:

- Replayed nonce is rejected.
- Bad signature consumes nonce.
- Unknown user nonce request is generic.
- Malformed registration payloads are rejected.
- Oversized public keys are rejected.
- Session token is hashed at rest.
- Security headers are present.
- Default signature algorithm is ML-DSA-65.

Run tests:

```powershell
cd D:\CNS-lab-el
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Expected result:

```text
Ran 7 tests
OK
```

## How To Explain “Quantum-Resistant”

Do not say this is a real quantum computer attack demo.

Say this:

> This project demonstrates a quantum-resistant authentication design by avoiding RSA/ECC and passwords during login. Authentication is done using ML-DSA-65 post-quantum digital signatures and fresh nonces.

Important points:

- Shor’s algorithm threatens RSA and elliptic-curve cryptography.
- This login flow does not use RSA or ECDSA.
- The browser uses ML-DSA-65 from `@noble/post-quantum`.
- The backend verifies ML-DSA-65 signatures with `pqcrypto`.
- The server stores only public verification material.
- A fresh nonce is required for every login.
- Captured login traffic cannot be replayed.

Honest limitation:

> This is still a research prototype, but the default signature path is now standardized ML-DSA-65. Production use would still require formal cryptographic review, key lifecycle design, and deployment hardening.

## How To Show It Is More Than Normal Login

### Demo 1: No Password Storage

Run:

```powershell
cd D:\CNS-lab-el
.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'backend'); from app import create_app; from models import User; app=create_app('development'); app.app_context().push(); print(User.__table__.columns.keys())"
```

Point out that there is no password column.

Expected fields include:

```text
id
username
public_key
signature_algorithm
signature_counter
signature_capacity
created_at
is_active
```

Presentation line:

> The server cannot leak passwords because it never stores passwords.

### Demo 2: Public Key Stored, Private Key Not Stored

Run:

```powershell
cd D:\CNS-lab-el
.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'backend'); from app import create_app; from models import User; app=create_app('development'); app.app_context().push(); u=User.query.filter_by(username='asish').first(); print('algorithm:', u.signature_algorithm); print('public key stored:', bool(u.public_key)); print('private key stored: no'); print('signature slots:', u.signature_counter, '/', u.signature_capacity)"
```

Presentation line:

> The backend stores public verification material only. The private signing key stays with the user.

### Demo 3: Wrong Private Key Fails

Steps:

1. Register a user.
2. Generate a different key bundle.
3. Try logging in with the registered username but the wrong private key.

Expected result:

```text
Authentication failed
```

Presentation line:

> Knowing the username is not enough. The attacker must possess the matching private key.

### Demo 4: Replay Attack Fails

Steps:

1. Login successfully.
2. Explain that an attacker captured `username + nonce + signature`.
3. Reuse the same nonce/signature.

Expected result:

```text
401 Invalid or expired nonce
```

Presentation line:

> Even captured valid login traffic cannot be reused because the nonce is single-use.

### Demo 5: Runtime Algorithm Panel

Show:

```text
Backend PQC: ML-DSA-65
Browser Default: ML-DSA-65
```

Presentation line:

> The current browser implementation uses ML-DSA-65, a NIST-standardized post-quantum signature. The backend also reports SPHINCS+-SHA2-256f through `pqcrypto`. The architecture keeps WOTS-SHA256 only as a legacy fallback and leaves XMSS as an extension point because no usable Python 3.14 package was available in this setup.

## Recommended Presentation Flow

1. Open the frontend console.
2. Show Runtime panel.
3. Register a new user.
4. Show generated public/private key separation.
5. Login successfully.
6. Show nonce/signature panel and API activity.
7. Show database columns with no password field.
8. Try wrong private key.
9. Show replay attack rejection.
10. End with honest limitations and production upgrade path.

## One-Minute Explanation

Use this in your viva/demo:

> This is not a normal password login. It is a passwordless challenge-response authentication system. During registration, the browser creates an ML-DSA-65 post-quantum keypair. The backend stores only the public key. During login, the backend sends a fresh nonce, and the browser signs `username + nonce` with the private key. The backend verifies the signature using the public key and then marks the nonce as used. This removes password storage, avoids RSA/ECC-based login primitives that are vulnerable to quantum attacks, and prevents replay attacks using single-use nonces.

## Remaining Limitations

This project is still a prototype.

Remaining production work:

- Keep the ML-DSA-65 implementation under review and document the key-envelope format.
- Add account recovery and key rotation.
- Use PostgreSQL/MySQL with migrations.
- Add deployment monitoring and CI.
- Perform formal cryptographic review.
- Add concurrency testing against a production database.

The best academic framing is:

> A working research prototype for passwordless, post-quantum-style authentication using hash-based digital signatures and replay-safe challenge-response.
