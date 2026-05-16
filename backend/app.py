"""
Quantum-Resistant Authentication System Backend

A Flask-based authentication system using post-quantum digital signatures
instead of passwords. Features include:

Authentication Method:
======================
- Registration: Store public key (not password)
- Login: Sign nonce with private key
- Verification: Server verifies signature using public key
- Result: Proves client owns private key → authenticated!

Post-Quantum Cryptography:
==========================
- Traditional RSA/ECDSA: Broken by quantum computers (Shor's algorithm)
- Post-Quantum: SPHINCS+, XMSS, ML-DSA use hash functions
- Hash functions: Believed resistant to quantum attacks
- Library: Uses liboqs (if available) or simulates with SHA256

Features:
=========
✓ No passwords transmitted or stored
✓ Digital signatures prove identity
✓ Nonce-based challenge-response
✓ One-time use nonces prevent replay attacks
✓ Rate limiting against brute force
✓ Session management with expiration
✓ Post-quantum resistant (SPHINCS+, XMSS, or ML-DSA)
✓ Secure logging and IP tracking

Security Stack:
===============
- Cryptography: Post-quantum digital signatures
- Transport: HTTPS recommended for production
- Sessions: Secure tokens with expiration
- Rate Limiting: Prevent brute force attacks
- Input Validation: All inputs validated
- Logging: Security events logged with IP/user-agent
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timezone
import logging
import os

from config import config
from models import db, User
from auth_routes import auth_bp, limiter as auth_limiter
from crypto_utils import QuantumSafeSignature
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix

# ============================================================================
# Application Factory
# ============================================================================

def create_app(config_name: str = None) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        config_name: Configuration environment ('development', 'production', 'testing')
        
    Returns:
        Configured Flask application
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    validate_runtime_config(app, config_name)

    if app.config.get('TRUST_PROXY_HEADERS'):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    
    # Initialize extensions
    db.init_app(app)
    CORS(
        app,
        resources={
            r"/auth/*": {
                "origins": app.config['CORS_ORIGINS'],
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "max_age": 600,
            }
        },
    )
    if auth_limiter is not None:
        auth_limiter.init_app(app)
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    # Register error handlers
    register_error_handlers(app)
    register_security_headers(app)
    
    # ================================================================
    # Shell Context & Routes
    # ================================================================
    
    @app.shell_context_processor
    def make_shell_context():
        """Provide convenient imports for flask shell"""
        return {
            'db': db,
            'User': User,
            'crypto': QuantumSafeSignature
        }
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'ok',
            'service': 'Quantum-Resistant Authentication System',
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }), 200
    
    # Create application context and initialize database
    with app.app_context():
        db.create_all()
        ensure_schema()
        app.logger.info(f"Database initialized for {config_name} environment")
    
    return app


def validate_runtime_config(app: Flask, config_name: str) -> None:
    """Fail fast for unsafe production settings."""
    if config_name != 'production':
        return

    if app.config.get('SECRET_KEY') == app.config.get('DEFAULT_DEV_SECRET'):
        raise RuntimeError('SECRET_KEY must be set to a strong unique value in production')

    if not os.environ.get('CORS_ORIGINS'):
        raise RuntimeError('CORS_ORIGINS must be set explicitly in production')

    if app.config.get('CORS_ORIGINS') == '*':
        raise RuntimeError('CORS_ORIGINS must be an explicit allowlist in production')

    if str(app.config.get('SQLALCHEMY_DATABASE_URI', '')).startswith('sqlite:'):
        raise RuntimeError('DATABASE_URL must point to a production database in production')

    if not app.config.get('SESSION_COOKIE_SECURE'):
        raise RuntimeError('SESSION_COOKIE_SECURE must be enabled in production')


def register_security_headers(app: Flask) -> None:
    """Attach conservative security headers to every response."""
    if not app.config.get('SECURITY_HEADERS_ENABLED', True):
        return

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=()'
        )
        response.headers.setdefault('Cache-Control', 'no-store')

        csp = app.config.get('CONTENT_SECURITY_POLICY')
        if csp:
            response.headers.setdefault('Content-Security-Policy', csp)

        if app.config.get('HSTS_ENABLED') and request.is_secure:
            max_age = int(app.config.get('HSTS_MAX_AGE', 31536000))
            response.headers.setdefault(
                'Strict-Transport-Security',
                f'max-age={max_age}; includeSubDomains'
            )

        return response


def ensure_schema() -> None:
    """Add columns introduced after the original classroom prototype."""
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())

    if 'users' in tables:
        user_columns = {column['name'] for column in inspector.get_columns('users')}
        with db.engine.begin() as connection:
            if 'signature_algorithm' not in user_columns:
                connection.execute(text(
                    "ALTER TABLE users ADD COLUMN signature_algorithm VARCHAR(64) "
                    "NOT NULL DEFAULT 'WOTS-SHA256'"
                ))
            if 'signature_counter' not in user_columns:
                connection.execute(text(
                    "ALTER TABLE users ADD COLUMN signature_counter INTEGER "
                    "NOT NULL DEFAULT 0"
                ))
            if 'signature_capacity' not in user_columns:
                connection.execute(text(
                    "ALTER TABLE users ADD COLUMN signature_capacity INTEGER"
                ))

    if 'nonces' in tables:
        nonce_columns = {column['name'] for column in inspector.get_columns('nonces')}
        if 'key_index' not in nonce_columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE nonces ADD COLUMN key_index INTEGER"))

# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging(app: Flask) -> None:
    """Setup application logging"""
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        handler = logging.FileHandler('logs/quantum_auth.log')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
    
    app.logger.info('Quantum-Resistant Authentication System started')

# ============================================================================
# Error Handlers
# ============================================================================

def register_error_handlers(app: Flask) -> None:
    """Register error handlers for API responses"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized'}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden'}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed'}), 405
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({'error': 'Too many requests. Please try again later.'}), 429

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({'error': 'Request body too large'}), 413
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Internal server error: {str(error)}')
        return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
