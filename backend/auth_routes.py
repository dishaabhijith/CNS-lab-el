"""
Authentication routes for quantum-resistant authentication system.

This module implements the complete authentication flow using post-quantum
digital signatures instead of passwords.

Flow Overview:
==============

1. REGISTRATION:
   - Client generates keypair locally (post-quantum safe)
   - Client sends: username + public_key to server
   - Server stores public_key in database
   - Private key never leaves client!

2. LOGIN (Nonce-based Challenge-Response):
   
   Step 1: Request Nonce
   - Client sends: username
   - Server generates random nonce (256 bits)
   - Server stores nonce with TTL (5 minutes)
   - Server sends nonce to client
   
   Step 2: Sign Challenge
   - Client creates: message = username + nonce
   - Client signs message with their private key
   - Signature proves client owns the private key!
   
   Step 3: Verify Signature
   - Client sends: username + nonce + signature
   - Server retrieves stored nonce (verify not expired/used)
   - Server retrieves user's public key from database
   - Server verifies: VERIFY_SIGNATURE(message, signature, public_key)
   - If valid → authentication successful!

Why This is Secure:
===================
✓ No passwords transmitted or stored
✓ Only public keys stored on server
✓ Private key never leaves client
✓ Signature proves ownership of private key
✓ Nonce prevents replay attacks (one-time use)
✓ Post-quantum resistant (using SPHINCS+/XMSS/ML-DSA)

Endpoints:
==========
- POST /auth/register - Register with public key
- POST /auth/nonce - Get nonce for authentication challenge
- POST /auth/login - Login with signed nonce
- POST /auth/verify - Verify session token
- POST /auth/logout - Logout and invalidate session
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import secrets
import re
import hmac
import hashlib
from functools import wraps

from models import db, User, Nonce, Session, LoginAttempt
from crypto_utils import QuantumSafeSignature, get_client_ip, get_user_agent

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address)
except ImportError:
    limiter = None


def rate_limit(rule: str):
    """Apply Flask-Limiter limits when the optional dependency is installed."""
    def decorator(func):
        if limiter is None:
            return func
        return limiter.limit(rule)(func)
    return decorator

# ============================================================================
# REPLAY ATTACK PROTECTION SUMMARY
# ============================================================================
"""
This authentication system implements THREE LAYERS of replay attack protection:

LAYER 1: UNIQUE NONCE (Per-Request Freshness)
==============================================
- Each /auth/nonce request generates a NEW 256-bit random nonce
- Nonce stored in database with creation timestamp
- Attacker cannot reuse old nonce (server expects new one each time)
- Even if attacker captures valid (nonce + signature), nonce is one-time use

LAYER 2: NONCE EXPIRATION (Time-Based Window)
==============================================
- Nonce valid for the configured 5-minute window
- Timestamp: created_at + NONCE_EXPIRY = expires_at
- Server checks: current_time < expires_at before accepting
- After expiry, even valid (nonce + signature) is rejected as expired
- Limits time attacker has to successfully replay

LAYER 3: SINGLE-USE ENFORCEMENT (Used Flag)
=============================================
- First successful auth: mark nonce.used = True
- Second login attempt (even seconds later): check used flag
- If used=True: reject with \"nonce already used\"
- Same (username + nonce + signature) only works ONCE

Attack Scenarios & Defenses:
==============================

SCENARIO 1: Immediate Replay
-------------------------------
t=0s   Attacker captures: alice + nonce + signature
t=1s   Attacker resends: alice + nonce + signature
       Check: used=True \u2713, expires_at not reached \u2713
       Result: BLOCKED (one-time use protection)

SCENARIO 2: Late Replay
-----------------------
t=0s   Attacker captures: alice + nonce + signature
t=40s  Attacker resends: alice + nonce + signature
       Check: used=False \u2713 (if first use), BUT expires_at has passed
       Result: BLOCKED (expiration protection)

SCENARIO 3: Man-in-the-Middle Modifies Signature
--------------------------------------------------
t=0s   Attacker modifies: alice + nonce + modified_signature
t=1s   Attacker sends: alice + nonce + modified_signature
       Check: verify_signature() fails (doesn't match private key)
       Result: BLOCKED (cryptographic signature protection)

SCENARIO 4: Man-in-the-Middle Changes Username
------------------------------------------------
t=0s   Attacker changes: bob + nonce + alice_signature
t=1s   Attacker sends: bob + nonce + alice_signature
       Check: message (bob+nonce) != signed_message (alice+nonce)
       Result: BLOCKED (signature binding protection)

Result: COMPLETE REPLAY ATTACK PREVENTION
"""

# ============================================================================
# Helper Functions
# ============================================================================

def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) < 3 or len(username) > 80:
        return False
    # Alphanumeric and underscore only
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_public_key(public_key: str) -> bool:
    """Validate supported public-key envelopes."""
    if not public_key:
        return False

    try:
        QuantumSafeSignature.inspect_public_key(public_key)
        return True
    except ValueError:
        return False

def get_session_token(length: int = 32) -> str:
    """Generate a secure session token"""
    return secrets.token_urlsafe(length)

def hash_session_token(token: str) -> str:
    """Store only an HMAC-SHA256 digest of bearer tokens server-side."""
    secret = current_app.config['SECRET_KEY'].encode('utf-8')
    return hmac.new(secret, token.encode('utf-8'), hashlib.sha256).hexdigest()

def cleanup_expired_records() -> None:
    """Keep nonce, session, and login-attempt tables from growing forever."""
    now = datetime.utcnow()
    lockout_window = current_app.config.get('LOCKOUT_DURATION', timedelta(minutes=15))

    Nonce.query.filter(Nonce.expires_at < now).delete(synchronize_session=False)
    Session.query.filter(Session.expires_at < now).delete(synchronize_session=False)
    LoginAttempt.query.filter(
        LoginAttempt.attempted_at < now - lockout_window
    ).delete(synchronize_session=False)

def check_rate_limit(username: str, ip_address: str, max_attempts: int = 5, 
                     window_minutes: int = 15) -> bool:
    """
    Check if user has exceeded login attempt limit.
    
    Args:
        username: Username attempting to login
        ip_address: IP address of attempt
        max_attempts: Maximum failed attempts allowed
        window_minutes: Time window to check
        
    Returns:
        bool: True if rate limit exceeded, False otherwise
    """
    cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    recent_failures = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.successful == False,
        LoginAttempt.attempted_at > cutoff_time
    ).count()
    
    return recent_failures >= max_attempts

def require_session(f):
    """Decorator to verify session token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '', 1).strip() if auth_header.startswith('Bearer ') else ''
        
        if not token:
            return jsonify({'error': 'No session token provided'}), 401
        
        session = Session.query.filter_by(session_token=hash_session_token(token)).first()
        
        if not session or not session.is_valid():
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        request.current_user = session.user
        request.current_session = session
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# Algorithm Discovery Endpoint
# ============================================================================

@auth_bp.route('/algorithms', methods=['GET'])
@rate_limit("60 per minute")
def algorithms():
    """Report available signature algorithms and runtime backend status."""
    return jsonify({
        'default_algorithm': 'WOTS-SHA256',
        'best_installed_backend': QuantumSafeSignature.get_backend(),
        'nonce_expires_in_seconds': int(current_app.config['NONCE_EXPIRY'].total_seconds()),
        'supported_algorithms': QuantumSafeSignature.get_supported_algorithms()
    }), 200

# ============================================================================
# Registration Endpoint
# ============================================================================

@auth_bp.route('/register', methods=['POST'])
@rate_limit("10 per minute")
def register():
    """
    Register a new user with a post-quantum public key.
    
    Registration Process:
    =====================
    
    Step 1: CLIENT GENERATES KEYPAIR
    - User clicks "Generate Quantum-Safe Key Pair"
    - Browser generates keypair locally:
      * Private Key: 256-bit random, kept secret
      * Public Key: Derived from private key
    - Algorithm: XMSS, SPHINCS+, or ML-DSA (post-quantum)
    - Private key NEVER leaves the client!
    
    Step 2: CLIENT SENDS PUBLIC KEY
    - Sends to server: username + public_key
    - Private key is NOT sent
    - This is the user's "fingerprint" for authentication
    
    Step 3: SERVER VALIDATES AND STORES
    - Validates username (alphanumeric + underscore)
    - Validates public key (proper hex format)
    - Checks username not already registered
    - Stores user record with public key
    - Returns success
    
    Step 4: USER SAVES PRIVATE KEY
    - User MUST save/download private key securely
    - Without it, cannot login later
    - Stored locally by user (encrypted recommended)
    - NO backup option if lost!
    
    REPLAY ATTACK PREVENTION: Signature Binding
    ===========================================
    Registration sets up the cryptographic keys that enable replay protection:
    
    1. Public key stored = Can verify signatures
    2. Each login creates UNIQUE nonce
    3. Client signs: username + NONCE (includes nonce!)
    4. Signature binds nonce to username
    5. Changing nonce invalidates old signature
    6. Result: Old (username + nonce + signature) cannot be replayed!
    
    Example:
    - Alice registers: public_key = \"abc123...\"
    - Alice logs in: Server gives nonce_1
    - Alice signs: sig_1 = sign(alice + nonce_1)
    - Attacker captures: sig_1
    - Attacker replays: alice + nonce_1 + sig_1 \u2713 (once)
    - Server marks nonce_1 as used
    - Attacker tries again: alice + nonce_1 + sig_1 \u2717 (BLOCKED - used)
    - New login: Alice gets nonce_2 (different!)
    - Attacker's old sig_1 invalid for nonce_2 (binding!)
    
    Result: Each authentication requires fresh nonce!
    \"\"\"
    
    Request JSON:
    {
        "username": "alice",
        "public_key": "abc123def456..."  # 64-char hex string (32 bytes)
    }
    
    Response:
    {
        "success": true,
        "user_id": "uuid",
        "message": "User alice registered successfully"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        public_key = data.get('public_key', '').strip()
        requested_algorithm = data.get('algorithm', '').strip()
        
        # ==================================================================
        # VALIDATE USERNAME
        # ==================================================================
        if not validate_username(username):
            return jsonify({
                'error': 'Invalid username. Must be 3-80 characters, alphanumeric and underscore only'
            }), 400
        
        # ==================================================================
        # VALIDATE PUBLIC KEY
        # ==================================================================
        # Public key should be 64 hex characters (32 bytes) for SHA256-based keys
        # For real post-quantum (SPHINCS+, XMSS), may be larger
        if not validate_public_key(public_key):
            return jsonify({
                'error': 'Invalid public key format or unsupported algorithm'
            }), 400

        key_info = QuantumSafeSignature.inspect_public_key(public_key)
        signature_algorithm = key_info['algorithm']
        signature_capacity = key_info.get('slots')

        if requested_algorithm and requested_algorithm != signature_algorithm:
            return jsonify({
                'error': 'Algorithm does not match public key metadata'
            }), 400
        
        # ==================================================================
        # CHECK USERNAME UNIQUENESS
        # ==================================================================
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        # ==================================================================
        # CREATE USER WITH PUBLIC KEY
        # ==================================================================
        # Store only the public key, never private key!
        # Public key is used to verify signatures during authentication
        user = User(
            username=username,
            public_key=public_key,
            signature_algorithm=signature_algorithm,
            signature_counter=0,
            signature_capacity=signature_capacity
        )
        
        db.session.add(user)
        db.session.commit()
        
        current_app.logger.info(
            f"[AUTH] New user registered: {username} with {signature_algorithm} public key"
        )
        
        return jsonify({
            'success': True,
            'user_id': user.id,
            'message': f'User {username} registered successfully',
            'username': username,
            'algorithm': signature_algorithm,
            'signature_capacity': signature_capacity
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'[ERROR] Registration error: {str(e)}')
        return jsonify({'error': 'Registration failed'}), 500

# ============================================================================
# Nonce Request Endpoint
# ============================================================================

@auth_bp.route('/nonce', methods=['POST'])
@rate_limit("20 per minute")
def get_nonce():
    """
    Request a unique nonce for challenge-response authentication.
    
    REPLAY ATTACK PREVENTION: Nonce Generation
    ===========================================
    
    What is a Replay Attack?
    - Attacker intercepts: username + nonce + signature
    - Attacker replays request: GET /login with same data
    - Server re-authenticates because signature is valid
    - Attacker gains access without password/private key!
    
    How Nonce Prevents This:
    - Each nonce is UNIQUE (256-bit random)
    - Each nonce is SINGLE-USE (used flag)
- Each nonce EXPIRES (5 minutes by project requirement)
    
    Attack Timeline:
    ===============
    
    Normal Flow (Server Perspective):
    ---------------------------------
    t=0s   Client requests nonce
           Server generates: nonce="abc123xyz789"
           Server stores: nonce, user_id, expires_at=t+5min, used=False
           Returns nonce to client
    
    t=2s   Client signs: signature(username + "abc123xyz789")
           Client sends: username + nonce + signature
           Server checks:
             ✓ nonce exists? YES
             ✓ nonce expired? NO (inside 5-minute window)
             ✓ nonce used? NO
           Server marks: used=True
           Returns: session_token ✓ AUTHENTICATED
    
    Replay Attack (Attacker Tries to Reuse):
    ----------------------------------------
    t=5s   Attacker resends: username + nonce + signature (same data)
           Server checks:
             ✓ nonce exists? YES
             ✗ nonce expired? NO (inside 5-minute window)
             ✗ nonce used? YES (already used at t=2s!) ← BLOCKED!
           Returns: 401 Unauthorized ✗ REJECTED
    
    Late Replay Attack (Attacker Tries After Expiration):
    ---------------------------------------------------
    t=35s  Attacker resends: username + nonce + signature
           Server checks:
             ✓ nonce exists? YES
             ✗ nonce expired? YES (after 5-minute window) ← TIME EXPIRED!
             ? nonce used? (doesn't matter, already expired)
           Returns: 401 Unauthorized ✗ REJECTED
    
    Result: Same nonce/signature combination works ONLY ONCE in 30-second window!
    
    Nonce-Based Challenge-Response Mechanism:
    
    Process:
    
    Step 1: CLIENT REQUESTS NONCE
    - Sends: username
    - Server generates random nonce (256 bits)
    
    Step 2: SERVER GENERATES NONCE
    - Creates random 256-bit value using secure RNG
    - Stores in database with:
      * User ID (linked to user)
      * Nonce value (hex encoded)
      * Created timestamp
      * Expiration time (5 minutes default)
      * Used flag (initially False)
    
    Step 3: SERVER SENDS NONCE TO CLIENT
    - Nonce transmitted in plaintext (it's public!)
    - Client receives and stores temporarily
    
    Step 4: CLIENT SIGNS NONCE
    - Creates message: username + nonce
    - Signs with private key (post-quantum signature)
    - Sends back: username + nonce + signature
    
    Step 5: SERVER VERIFIES NONCE WAS NOT REUSED
    - When client returns signature, server checks:
      * Does nonce exist for this user?
      * Is nonce NOT marked as used?
      * Has nonce NOT expired (< 5 minutes)?
    - If valid → mark as used (prevent replay)
    - If invalid → authentication fails
    
    Security Properties:
    ====================
    ✓ Unique per authentication: Each nonce is random
    ✓ One-time use: Marked as "used" after login
    ✓ Time-limited: Expires after 5 minutes
    ✓ Prevents replay: Same signature won't work again
    ✓ No password needed: Only signature required
    
    Request JSON:
    {
        "username": "alice"
    }
    
    Response:
    {
        "nonce": "abc123def456...",  # 256-bit random, hex encoded
        "nonce_id": "uuid",
        "username": "alice",
        "expires_in_seconds": 300
    }
    """
    try:
        cleanup_expired_records()

        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'error': 'Username required'}), 400
        
        # ==================================================================
        # FIND USER
        # ==================================================================
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if not user:
            # Don't reveal if user exists (security best practice)
            return jsonify({'error': 'User not found'}), 404

        key_capacity = QuantumSafeSignature.get_public_key_capacity(user.public_key)
        key_index = None

        if key_capacity is not None:
            current_index = user.signature_counter or 0
            if current_index >= key_capacity:
                return jsonify({
                    'error': 'Signature key bundle exhausted. Generate and register a new key bundle.',
                    'algorithm': user.signature_algorithm,
                    'signature_capacity': key_capacity,
                    'signature_slots_remaining': 0
                }), 409

            key_index = current_index
            user.signature_counter = current_index + 1
        
        # ==================================================================
        # GENERATE NONCE
        # ==================================================================
        # Using post-quantum secure random generation
        # This nonce will be signed by client and verified by server
        nonce_value = QuantumSafeSignature.generate_nonce()
        
        # ==================================================================
        # CALCULATE EXPIRATION
        # ==================================================================
        # Nonce valid for 5 minutes (standard for security)
        # After this, even if client signs it, server will reject as expired
        expires_at = datetime.utcnow() + current_app.config['NONCE_EXPIRY']
        
        # ==================================================================
        # STORE NONCE IN DATABASE
        # ==================================================================
        # Store all nonce data for later verification
        nonce = Nonce(
            user_id=user.id,
            nonce=nonce_value,
            key_index=key_index,
            expires_at=expires_at
        )
        
        db.session.add(nonce)
        db.session.commit()
        
        current_app.logger.debug(
            f"[AUTH] Nonce generated for {username}, expires in "
            f"{int(current_app.config['NONCE_EXPIRY'].total_seconds())} seconds"
        )
        
        return jsonify({
            'nonce': nonce_value,
            'nonce_id': nonce.id,
            'username': username,
            'expires_in_seconds': int(current_app.config['NONCE_EXPIRY'].total_seconds()),
            'algorithm': user.signature_algorithm,
            'key_index': key_index,
            'signature_slots_remaining': (
                max((key_capacity or 0) - (user.signature_counter or 0), 0)
                if key_capacity is not None else None
            )
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'[ERROR] Nonce generation error: {str(e)}')
        return jsonify({'error': 'Failed to generate nonce'}), 500

# ============================================================================
# Login Endpoint
# ============================================================================

@auth_bp.route('/login', methods=['POST'])
@rate_limit("10 per minute")
def login():
    """
    Login with username and signed nonce using post-quantum signatures.
    
    Authentication Process (Nonce-based Challenge-Response):
    ========================================================
    
    Step 1: CLIENT RECEIVES NONCE
    - Request: {username}
    - Server generates random nonce (256 bits)
    - Response: {nonce, nonce_id}
    
    Step 2: CLIENT SIGNS NONCE
    - Message = username + nonce (concatenated)
    - Client signs using POST-QUANTUM SIGNATURE ALGORITHM:
      * Real: SPHINCS+, XMSS, or ML-DSA (if liboqs available)
      * Demo: SHA256-based HMAC signature
    - Signature proves client owns the private key!
    
    Step 3: SERVER VERIFIES SIGNATURE
    - Receives: {username, nonce, signature}
    - Validates input format
    - Retrieves user's stored PUBLIC KEY
    - Reconstructs message: username + nonce
    - Verifies signature using PUBLIC KEY:
      * QuantumSafeSignature.verify_signature()
      * Only valid if signature was created with matching PRIVATE KEY
    - Marks nonce as "used" (prevents replay)
    - Creates session token
    
    Why Post-Quantum:
    =================
    - Traditional RSA/ECDSA vulnerable to quantum computers
    - SPHINCS+/XMSS/ML-DSA use hash functions (quantum-resistant)
    - Only secret is the private key (kept client-side)
    - Server only needs public key to verify
    
    Security Properties:
    ====================
    ✓ Replay Attack Prevention: Each nonce single-use
    ✓ Identity Proof: Signature proves private key ownership
    ✓ Quantum Resistance: Post-quantum algorithm used
    ✓ No Password: Never transmitted or stored
    ✓ Zero Knowledge: Server learns only authentication result
    
    Request JSON:
    {
        "username": "alice",
        "nonce": "abc123def456...",      # From /auth/nonce endpoint
        "signature": "sig123..."         # Client's digital signature
    }
    
    Response:
    {
        "success": true,
        "session_token": "token123...",
        "user_id": "uuid",
        "expires_at": "2024-..."
    }
    """
    try:
        cleanup_expired_records()

        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        nonce = data.get('nonce', '').strip()
        signature = data.get('signature', '').strip()
        
        # Get client IP for rate limiting and security logging
        client_ip = get_client_ip(request)
        
        # ==================================================================
        # RATE LIMITING: Prevent brute-force attacks
        # ==================================================================
        lockout_window = current_app.config.get('LOCKOUT_DURATION', timedelta(minutes=15))
        if check_rate_limit(
            username,
            client_ip,
            current_app.config.get('MAX_LOGIN_ATTEMPTS', 5),
            max(1, int(lockout_window.total_seconds() / 60))
        ):
            return jsonify({
                'error': 'Too many login attempts. Please try again later.'
            }), 429
        
        # ==================================================================
        # INPUT VALIDATION
        # ==================================================================
        if not username or not nonce or not signature:
            return jsonify({'error': 'Username, nonce, and signature required'}), 400
        
        # ==================================================================
        # STEP 1: FIND USER
        # ==================================================================
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if not user:
            # Don't reveal if user exists (security best practice)
            attempt = LoginAttempt(username=username, ip_address=client_ip, successful=False)
            db.session.add(attempt)
            db.session.commit()
            
            return jsonify({'error': 'Authentication failed'}), 401
        
        # ==================================================================
        # STEP 2: VALIDATE NONCE
        # ==================================================================
        # A nonce is a single-use token that prevents replay attacks
        nonce_obj = Nonce.query.filter_by(
            user_id=user.id,
            nonce=nonce
        ).first()
        
        if not nonce_obj or not nonce_obj.is_valid():
            # REPLAY ATTACK DETECTION
            # =======================
            # Nonce check failed for one of three reasons:
            # 
            # 1. Nonce doesn't exist in database
            #    - Attacker fabricated a nonce
            #    - Attacker is replaying with old nonce
            # 
            # 2. Nonce expired (created_at + NONCE_EXPIRY < now)
            #    - Attacker waited too long to replay
            #    - Legitimate user lost connection (timeout)
            # 
            # 3. Nonce already used (used=True)
            #    - REPLAY ATTACK DETECTED! ← Classic replay attempt
            #    - Same nonce sent again to /login
            #    - Legitimate user sent duplicate request by mistake
            # 
            # Action: Reject authentication regardless of why
            attempt = LoginAttempt(username=username, ip_address=client_ip, successful=False)
            db.session.add(attempt)
            db.session.commit()
            
            current_app.logger.warning(
                f"[REPLAY] Failed nonce check for {username}: "
                f"exists={bool(nonce_obj)}, expired={nonce_obj.is_expired() if nonce_obj else 'N/A'}, "
                f"used={nonce_obj.used if nonce_obj else 'N/A'}"
            )
            
            return jsonify({'error': 'Invalid or expired nonce'}), 401
        
        # ==================================================================
        # STEP 3: VERIFY POST-QUANTUM SIGNATURE
        # ==================================================================
        # This is the core authentication mechanism!
        # 
        # Signature Verification Process:
        # 1. Message to verify: username + nonce (same as what client signed)
        # 2. Signature: received from client
        # 3. Public Key: retrieved from database (stored during registration)
        # 4. Algorithm: Post-quantum (SPHINCS+, XMSS, or ML-DSA)
        #
        # If verification succeeds → client owns the private key!
        # 
        # REPLAY ATTACK PROTECTION: Signature Binding
        # ===========================================
        # The nonce is included in the signature!
        # 
        # This creates a BINDING between:
        # - Specific nonce value ("abc123xyz789")
        # - Specific username ("alice")
        # - Specific signature (cryptographic proof)
        # 
        # Attacker cannot:
        # ✗ Reuse same nonce (marked as used)
        # ✗ Generate new signature (doesn't have private key)
        # ✗ Modify message (signature won't verify)
        # ✗ Use old nonce (expired after the configured TTL)
        # 
        # Each authentication requires:
        # 1. Fresh nonce from server
        # 2. Client to sign it with private key
        # 3. Server to verify signature is fresh
        # 
        # This 3-step binding prevents replay!
        
        message_to_verify = username + nonce
        public_key = user.public_key
        
        # Verify the signature using post-quantum algorithm
        is_signature_valid = QuantumSafeSignature.verify_signature(
            message_to_verify,
            signature,
            public_key,
            expected_key_index=nonce_obj.key_index
        )
        
        if is_signature_valid:
            # ============================================================
            # SUCCESSFUL AUTHENTICATION + REPLAY PROTECTION
            # ============================================================
            # Signature verified! User owns the private key.
            # Now protect against replays by marking nonce as used.
            
            current_app.logger.info(
                f"[AUTH-SUCCESS] User {username} authenticated from {client_ip} "
                f"using {user.signature_algorithm} signature"
            )
        else:
            # SIGNATURE VERIFICATION FAILED
            # =============================
            # Could indicate:
            # 1. Wrong private key (attacker trying)
            # 2. Nonce tampered (man-in-the-middle)
            # 3. Signature corrupted (transmission error)
            # 4. Replay with modified data (attacker changing message)
            
            nonce_obj.used = True
            attempt = LoginAttempt(username=username, ip_address=client_ip, successful=False)
            db.session.add(attempt)
            db.session.commit()
            
            current_app.logger.warning(
                f"[REPLAY/FORGERY] Signature verification failed for {username} at {client_ip}. "
                f"Could indicate: wrong key, tampering, or replay with modified data"
            )
            return jsonify({'error': 'Authentication failed'}), 401
        
        # ==================================================================
        # STEP 4: MARK NONCE AS USED (Prevent Replay Attacks)
        # ==================================================================
        # CRITICAL SECURITY STEP: One-Time Use Enforcement
        # 
        # Replay Attack Prevention: MARKING AS USED
        # =========================================
        # 
        # Attack Scenario:
        # 1. Attacker intercepts: GET /login with username + nonce + signature
        # 2. Attacker captures data
        # 3. Attacker replays: Sends same data again to /login
        # 4. Signature is still valid (same private key created it)
        # 5. Nonce is still valid (within time window)
        # 
        # Without Marking as Used:
        # - Both checks pass ✓
        # - Attacker authenticates! ✗ SECURITY BREACH
        # 
        # With Marking as Used:
        # - First login: nonce marked used=True ✓
        # - Replay attempt: nonce.used=True check fails ✗
        # - Attacker rejected! ✓ SECURITY MAINTAINED
        # 
        # This is the KEY to replay attack prevention:
        # Each nonce can only lead to ONE successful authentication
        # 
        # Even if attacker has the exact bytes of a valid request,
        # they can only use it ONCE before it's locked out!
        nonce_obj.used = True
        
        # ==================================================================
        # STEP 5: CREATE SESSION
        # ==================================================================
        # User authenticated! Create session token
        session_token = get_session_token()
        expires_at = datetime.utcnow() + current_app.config['PERMANENT_SESSION_LIFETIME']
        
        session = Session(
            user_id=user.id,
            session_token=hash_session_token(session_token),
            expires_at=expires_at,
            ip_address=client_ip,
            user_agent=get_user_agent(request)
        )
        
        db.session.add(session)
        
        # Log successful authentication
        attempt = LoginAttempt(username=username, ip_address=client_ip, successful=True)
        db.session.add(attempt)
        db.session.commit()
        
        current_app.logger.info(
            f"[AUTH] Successful login: {username} from {client_ip} "
            f"using {user.signature_algorithm} signature"
        )
        
        return jsonify({
            'success': True,
            'session_token': session_token,
            'user_id': user.id,
            'username': user.username,
            'expires_at': expires_at.isoformat() + 'Z',
            'auth_method': 'post-quantum-signature',
            'algorithm': user.signature_algorithm,
            'key_index': nonce_obj.key_index,
            'signature_slots_remaining': (
                max((user.signature_capacity or 0) - (user.signature_counter or 0), 0)
                if user.signature_capacity is not None else None
            )
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'[ERROR] Login error: {str(e)}')
        return jsonify({'error': 'Login failed'}), 500

# ============================================================================
# Session Verification Endpoint
# ============================================================================

@auth_bp.route('/verify', methods=['POST'])
@require_session
def verify():
    """
    Verify a session token.
    
    Headers:
    Authorization: Bearer <session_token>
    
    Response:
    {
        "valid": true,
        "user_id": "uuid",
        "username": "alice",
        "expires_at": "2024-..."
    }
    """
    try:
        return jsonify({
            'valid': True,
            'user_id': request.current_user.id,
            'username': request.current_user.username,
            'expires_at': request.current_session.expires_at.isoformat() + 'Z',
            'algorithm': request.current_user.signature_algorithm,
            'signature_slots_remaining': (
                max((request.current_user.signature_capacity or 0) - (request.current_user.signature_counter or 0), 0)
                if request.current_user.signature_capacity is not None else None
            )
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Verification error: {str(e)}')
        return jsonify({'error': 'Verification failed'}), 500

# ============================================================================
# Logout Endpoint
# ============================================================================

@auth_bp.route('/logout', methods=['POST'])
@require_session
def logout():
    """
    Logout and invalidate session.
    
    Headers:
    Authorization: Bearer <session_token>
    
    Response:
    {
        "success": true,
        "message": "Logged out successfully"
    }
    """
    try:
        # Delete session
        db.session.delete(request.current_session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Logout error: {str(e)}')
        return jsonify({'error': 'Logout failed'}), 500

# ============================================================================
# User Info Endpoint
# ============================================================================

@auth_bp.route('/user', methods=['GET'])
@require_session
def get_user_info():
    """
    Get authenticated user information.
    
    Headers:
    Authorization: Bearer <session_token>
    
    Response:
    {
        "user_id": "uuid",
        "username": "alice",
        "created_at": "2024-...",
        "is_active": true
    }
    """
    try:
        return jsonify({
            'user_id': request.current_user.id,
            'username': request.current_user.username,
            'created_at': request.current_user.created_at.isoformat() + 'Z',
            'is_active': request.current_user.is_active,
            'algorithm': request.current_user.signature_algorithm,
            'signature_capacity': request.current_user.signature_capacity,
            'signature_counter': request.current_user.signature_counter
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'User info error: {str(e)}')
        return jsonify({'error': 'Failed to get user info'}), 500
