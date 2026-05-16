import os
from datetime import timedelta
from typing import List, Union

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_csv(name: str, default: str) -> Union[List[str], str]:
    value = os.environ.get(name, default).strip()
    if value == "*":
        return "*"
    return [item.strip() for item in value.split(",") if item.strip()]

class Config:
    """Base configuration"""
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///quantum_auth.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEFAULT_DEV_SECRET = 'dev-secret-key-change-in-production'
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=_env_int('PERMANENT_SESSION_LIFETIME', 86400))
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TOKEN_BYTES = _env_int('SESSION_TOKEN_BYTES', 32)
    BIND_SESSION_TO_IP = _env_bool('BIND_SESSION_TO_IP', False)
    BIND_SESSION_TO_USER_AGENT = _env_bool('BIND_SESSION_TO_USER_AGENT', False)
    
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
    NONCE_EXPIRY = timedelta(seconds=_env_int('NONCE_EXPIRY_SECONDS', 300))
    NONCE_LENGTH = _env_int('NONCE_LENGTH_BYTES', 32)
    
    # Security
    MAX_LOGIN_ATTEMPTS = _env_int('MAX_LOGIN_ATTEMPTS', 5)
    LOCKOUT_DURATION = timedelta(seconds=_env_int('LOCKOUT_DURATION_SECONDS', 900))
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    RATELIMIT_ENABLED = _env_bool('RATELIMIT_ENABLED', True)
    MAX_CONTENT_LENGTH = _env_int('MAX_CONTENT_LENGTH', 256 * 1024)
    MAX_PUBLIC_KEY_CHARS = _env_int('MAX_PUBLIC_KEY_CHARS', 96 * 1024)
    MAX_SIGNATURE_CHARS = _env_int('MAX_SIGNATURE_CHARS', 96 * 1024)
    TRUST_PROXY_HEADERS = _env_bool('TRUST_PROXY_HEADERS', False)

    # Browser/API hardening
    CORS_ORIGINS = _env_csv(
        'CORS_ORIGINS',
        'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173,http://localhost:8000,http://127.0.0.1:8000'
    )
    SECURITY_HEADERS_ENABLED = _env_bool('SECURITY_HEADERS_ENABLED', True)
    HSTS_ENABLED = _env_bool('HSTS_ENABLED', False)
    HSTS_MAX_AGE = _env_int('HSTS_MAX_AGE', 31536000)
    CONTENT_SECURITY_POLICY = os.environ.get(
        'CONTENT_SECURITY_POLICY',
        "default-src 'none'; frame-ancestors 'none'"
    )

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    HSTS_ENABLED = True

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    CORS_ORIGINS = ['http://localhost:5173']
    SECRET_KEY = 'testing-secret-key'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
