import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SQLALCHEMY_DATABASE_URI = 'sqlite:///quantum_auth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Nonce configuration (Replay Attack Prevention)
    # ================================================
    # Short expiration time prevents replay attacks:
    # - Attacker intercepts: username + nonce + signature
    # - Attacker replays the request later
    # - Server rejects: nonce expired!
    # 
    # The synopsis specifies a 5-minute nonce lifetime. Single-use nonce
    # tracking still prevents immediate replay inside that window.
    # 
    # Shorter = More secure but higher false-reject rate
    # Longer = Fewer false-rejects but more replay window
    NONCE_EXPIRY = timedelta(minutes=5)  # 5 minutes (synopsis requirement)
    NONCE_LENGTH = 32  # 32 bytes = 256 bits (256-bit random nonce)
    
    # Security
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
