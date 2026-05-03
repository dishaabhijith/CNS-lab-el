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

from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import logging
import os

from config import config
from models import db
from auth_routes import auth_bp
from crypto_utils import QuantumSafeSignature

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
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, resources={r"/auth/*": {"origins": "*"}})
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Create application context and initialize database
    with app.app_context():
        db.create_all()
        app.logger.info(f"Database initialized for {config_name} environment")
    
    return app

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
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Internal server error: {str(error)}')
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# CLI Commands
# ============================================================================

@app.shell_context_processor
def make_shell_context():
    """Provide convenient imports for flask shell"""
    return {
        'db': db,
        'User': db.Model.registry.mappers[0].class_ if db.Model.registry.mappers else None,
        'crypto': QuantumSafeSignature
    }

# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'Quantum-Resistant Authentication System',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
