from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import uuid

db = SQLAlchemy()

class User(db.Model):
    """User model - stores username and public key instead of password"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    public_key = db.Column(db.Text, nullable=False)  # Stored as base64 or hex
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    nonces = db.relationship('Nonce', backref='user', lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('Session', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Nonce(db.Model):
    """
    Nonce model - Single-use token to prevent replay attacks.
    
    Replay Attack Prevention Mechanism:
    ===================================
    A replay attack is when an attacker:
    1. Intercepts a valid authentication request: username + nonce + signature
    2. Records the entire request
    3. Resends the same request later to login as that user
    
    Protection Strategy:
    -------------------
    Each nonce is SINGLE-USE:
    
    Step 1: Client requests nonce
    - Server generates random 256-bit nonce
    - Server stores: nonce, user_id, created_at, expires_at, used=False
    
    Step 2: Client signs challenge with private key
    - Creates signature of: username + nonce
    
    Step 3: Server verifies signature
    - Server checks: nonce exists, not expired, not used
    - If all valid: marks nonce.used = True
    - Creates session
    
    Step 4: Replay attempt (attacker sends same request again)
    - Server checks nonce.used = True
    - Server rejects: "Nonce already used"
    - Authentication fails!
    
    Double Protection:
    - used flag: One-time use (prevents reuse)
    - expires_at: Time limit (prevents late replay)
    
    Even if attacker captures the signature, they can only use it ONCE!
    After that, the nonce is marked as used and rejected forever.
    """
    __tablename__ = 'nonces'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    nonce = db.Column(db.String(256), nullable=False, unique=True)  # Random, unique, hex-encoded
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)  # Tight TTL prevents late replay
    used = db.Column(db.Boolean, default=False)  # Single-use enforcement
    
    def __repr__(self):
        return f'<Nonce {self.nonce[:16]}...>'
    
    def is_expired(self) -> bool:
        """
        Check if nonce has exceeded expiration time.
        
        Replay Attack Prevention: TIME-BASED
        - If nonce expired, reject even if unused
        - Limits time window attacker can use captured signature
        - Default: 30 seconds (tight but realistic for network latency)
        
        Returns: True if past expires_at time
        """
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if nonce is valid for authentication.
        
        Replay Attack Prevention: DUAL CHECKS
        1. Expiration check: Current time < expires_at
        2. Used check: used = False (never used before)
        
        Both must pass for authentication:
        ✓ Expired? NO (within 30-second window)
        ✓ Used? NO (first use of this nonce)
        
        Result: Valid → proceed to signature verification
        Result: Invalid → reject authentication attempt
        
        Returns: True if both checks pass, False otherwise
        """
        return not self.is_expired() and not self.used

class Session(db.Model):
    """Session model - authenticated user sessions"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(256), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    
    def __repr__(self):
        return f'<Session {self.session_token[:16]}...>'
    
    def is_valid(self):
        """Check if session is still valid"""
        return datetime.utcnow() < self.expires_at
    
    def is_expired(self):
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at

class LoginAttempt(db.Model):
    """Track login attempts for rate limiting"""
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    successful = db.Column(db.Boolean, default=False)
    attempted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} from {self.ip_address}>'
