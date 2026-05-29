import os
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, BACKEND)

from app import create_app, ensure_schema  # noqa: E402
from crypto_utils import QuantumSafeSignature  # noqa: E402
from models import db, Session  # noqa: E402


class AuthSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            ensure_schema()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    def register_user(self, username='alice', slots=4):
        public_key, private_key = QuantumSafeSignature.generate_keypair(slots)
        response = self.client.post('/auth/register', json={
            'username': username,
            'public_key': public_key,
            'algorithm': QuantumSafeSignature.SIGNATURE_ALGORITHM,
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return public_key, private_key

    def request_nonce(self, username='alice'):
        response = self.client.post('/auth/nonce', json={'username': username})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def login_payload(self, username, private_key, nonce_data):
        nonce = nonce_data['nonce']
        key_index = nonce_data['key_index'] or 0
        signature = QuantumSafeSignature.sign_message(username + nonce, private_key, key_index)
        return {
            'username': username,
            'nonce': nonce,
            'signature': signature,
        }

    def test_replayed_nonce_is_rejected(self):
        _, private_key = self.register_user()
        nonce_data = self.request_nonce()
        payload = self.login_payload('alice', private_key, nonce_data)

        first = self.client.post('/auth/login', json=payload)
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))

        replay = self.client.post('/auth/login', json=payload)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.get_json()['error'], 'Invalid or expired nonce')

    def test_default_signature_algorithm_is_ml_dsa(self):
        public_key, private_key = QuantumSafeSignature.generate_keypair()

        self.assertEqual(QuantumSafeSignature.get_public_key_algorithm(public_key), 'ML-DSA-65')
        self.assertEqual(QuantumSafeSignature.get_private_key_algorithm(private_key), 'ML-DSA-65')
        self.assertIsNone(QuantumSafeSignature.get_public_key_capacity(public_key))

    def test_bad_signature_consumes_nonce(self):
        _, private_key = self.register_user()
        nonce_data = self.request_nonce()
        nonce = nonce_data['nonce']
        key_index = nonce_data['key_index'] or 0

        bad_signature = QuantumSafeSignature.sign_message('tampered' + nonce, private_key, key_index)
        bad = self.client.post('/auth/login', json={
            'username': 'alice',
            'nonce': nonce,
            'signature': bad_signature,
        })
        self.assertEqual(bad.status_code, 401)

        valid_after_failure = self.client.post(
            '/auth/login',
            json=self.login_payload('alice', private_key, nonce_data),
        )
        self.assertEqual(valid_after_failure.status_code, 401)
        self.assertEqual(valid_after_failure.get_json()['error'], 'Invalid or expired nonce')

    def test_unknown_user_nonce_response_is_generic(self):
        response = self.client.post('/auth/nonce', json={'username': 'missing_user'})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()['error'], 'Authentication challenge unavailable')

    def test_malformed_and_oversized_registration_payloads_are_rejected(self):
        malformed = self.client.post(
            '/auth/register',
            data='not-json',
            content_type='text/plain',
        )
        self.assertEqual(malformed.status_code, 400)

        oversized = self.client.post('/auth/register', json={
            'username': 'alice',
            'public_key': 'x' * (self.app.config['MAX_PUBLIC_KEY_CHARS'] + 1),
        })
        self.assertEqual(oversized.status_code, 400)

    def test_session_token_is_hashed_at_rest(self):
        _, private_key = self.register_user()
        nonce_data = self.request_nonce()
        response = self.client.post(
            '/auth/login',
            json=self.login_payload('alice', private_key, nonce_data),
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        session_token = response.get_json()['session_token']

        with self.app.app_context():
            stored_session = Session.query.first()
            self.assertIsNotNone(stored_session)
            self.assertNotEqual(stored_session.session_token, session_token)
            self.assertEqual(len(stored_session.session_token), 64)

    def test_security_headers_are_present(self):
        response = self.client.get('/health')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn('frame-ancestors', response.headers['Content-Security-Policy'])


if __name__ == '__main__':
    unittest.main()
