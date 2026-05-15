#!/usr/bin/env python3
"""
Simple Python client for Quantum-Resistant Authentication System

This script demonstrates the complete authentication flow:
1. Generate keypair locally
2. Register with server (send public key)
3. Request login nonce
4. Sign nonce with private key
5. Login with signature
6. Verify success

Usage:
    python client.py [username] [server_url]
    
Examples:
    python client.py alice http://localhost:5000
    python client.py bob                           # Uses http://localhost:5000
"""

import sys
import json
import requests
import os
from typing import Tuple, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
from crypto_utils import QuantumSafeSignature

# ============================================================================
# CRYPTOGRAPHIC FUNCTIONS (matches backend/crypto_utils.py)
# ============================================================================

def generate_nonce(length: int = 32) -> str:
    """Generate a random 256-bit nonce and return as hex string."""
    return QuantumSafeSignature.generate_nonce(length)


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a simple keypair for demonstration.
    
    The default client uses the same WOTS-SHA256 browser-compatible
    signature bundle as the web UI.
    
    Returns:
        (public_key_hex, private_key_hex) - Both as hex strings
    """
    return QuantumSafeSignature.generate_keypair()


def sign_message(message: str, private_key_hex: str, key_index: int = 0) -> str:
    """
    Sign a message with the private key.
    
    Args:
        message: The message to sign (username + nonce)
        private_key_hex: Private key as hex string
        
    Returns:
        Signature as hex string
    """
    return QuantumSafeSignature.sign_message(message, private_key_hex, key_index)


def verify_signature(message: str, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify a message signature (for demonstration purposes).
    
    Note: This is for understanding the flow. The server does actual verification.
    """
    return QuantumSafeSignature.verify_signature(message, signature_hex, public_key_hex)


# ============================================================================
# CLIENT AUTHENTICATION FLOW
# ============================================================================

class QuantumAuthClient:
    """Client for quantum-resistant authentication system."""
    
    def __init__(self, username: str, server_url: str = "http://localhost:5000"):
        self.username = username
        self.server_url = server_url.rstrip('/')
        self.public_key = None
        self.private_key = None
        self.nonce = None
        self.key_index = 0
        self.session_token = None
        
    def print_step(self, step: int, title: str, content: str = ""):
        """Print a formatted step message."""
        print(f"\n{'─' * 70}")
        print(f"STEP {step}: {title}")
        print('─' * 70)
        if content:
            print(content)
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"✓ {message}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"✗ {message}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"  {message}")
    
    # ========================================================================
    # STEP 1: Generate Keypair
    # ========================================================================
    def step1_generate_keypair(self):
        """Generate keypair locally."""
        self.print_step(1, "Generate Quantum-Safe Keypair (Local)")
        
        try:
            self.public_key, self.private_key = generate_keypair()
            self.print_success("Keypair generated successfully")
            self.print_info(f"Public Key:  {self.public_key[:32]}...")
            self.print_info(f"Private Key: {self.private_key[:32]}...")
            return True
        except Exception as e:
            self.print_error(f"Failed to generate keypair: {e}")
            return False
    
    # ========================================================================
    # STEP 2: Register with Server
    # ========================================================================
    def step2_register(self) -> bool:
        """Register user with public key."""
        self.print_step(2, "Register with Server")
        
        try:
            url = f"{self.server_url}/auth/register"
            payload = {
                "username": self.username,
                "public_key": self.public_key,
                "algorithm": "WOTS-SHA256"
            }
            
            self.print_info(f"POST {url}")
            self.print_info(f"Payload: username='{self.username}', public_key='{self.public_key[:32]}...'")
            
            response = requests.post(url, json=payload, timeout=5)
            
            if response.status_code == 201:
                self.print_success(f"Registration successful (Status: {response.status_code})")
                self.print_info(f"Response: {response.json()}")
                return True
            else:
                self.print_error(f"Registration failed (Status: {response.status_code})")
                self.print_info(f"Response: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            self.print_error(f"Cannot connect to server at {self.server_url}")
            self.print_info("Make sure Flask backend is running: python backend/app.py")
            return False
        except Exception as e:
            self.print_error(f"Registration error: {e}")
            return False
    
    # ========================================================================
    # STEP 3: Request Login Nonce
    # ========================================================================
    def step3_request_nonce(self) -> bool:
        """Request nonce for authentication challenge."""
        self.print_step(3, "Request Login Nonce")
        
        try:
            url = f"{self.server_url}/auth/nonce"
            payload = {"username": self.username}
            
            self.print_info(f"POST {url}")
            self.print_info(f"Payload: username='{self.username}'")
            
            response = requests.post(url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.nonce = data.get('nonce')
                self.key_index = data.get('key_index', 0)
                self.print_success(f"Nonce received (Status: {response.status_code})")
                self.print_info(f"Nonce: {self.nonce}")
                self.print_info(f"Key slot: {self.key_index}")
                self.print_info(f"Expires in: {data.get('expires_in_seconds', 'unknown')} seconds")
                return True
            else:
                self.print_error(f"Failed to get nonce (Status: {response.status_code})")
                self.print_info(f"Response: {response.text}")
                return False
                
        except Exception as e:
            self.print_error(f"Nonce request error: {e}")
            return False
    
    # ========================================================================
    # STEP 4: Sign Nonce with Private Key
    # ========================================================================
    def step4_sign_nonce(self) -> bool:
        """Sign the username + nonce with private key."""
        self.print_step(4, "Sign Nonce with Private Key (Local)")
        
        try:
            # Message is username + nonce (exactly as server expects)
            message = f"{self.username}{self.nonce}"
            
            self.print_info(f"Message to sign: '{message}'")
            
            self.signature = sign_message(message, self.private_key, self.key_index)
            
            self.print_success("Signature created successfully")
            self.print_info(f"Signature: {self.signature[:32]}...")
            return True
            
        except Exception as e:
            self.print_error(f"Signature error: {e}")
            return False
    
    # ========================================================================
    # STEP 5: Login with Signature
    # ========================================================================
    def step5_login(self) -> bool:
        """Send signature to server for authentication."""
        self.print_step(5, "Login with Signature")
        
        try:
            url = f"{self.server_url}/auth/login"
            payload = {
                "username": self.username,
                "nonce": self.nonce,
                "signature": self.signature
            }
            
            self.print_info(f"POST {url}")
            self.print_info(f"Payload: username='{self.username}', nonce='{self.nonce}', "
                          f"signature='{self.signature[:32]}...'")
            
            response = requests.post(url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.session_token = data.get('session_token')
                self.print_success(f"Authentication successful (Status: {response.status_code})")
                self.print_info(f"Session Token: {self.session_token[:32]}...")
                self.print_info(f"Expires at: {data.get('expires_at', 'unknown')}")
                return True
            else:
                self.print_error(f"Authentication failed (Status: {response.status_code})")
                self.print_info(f"Response: {response.text}")
                return False
                
        except Exception as e:
            self.print_error(f"Login error: {e}")
            return False
    
    # ========================================================================
    # STEP 6: Verify Session (Optional)
    # ========================================================================
    def step6_verify_session(self) -> bool:
        """Verify that session token is valid."""
        self.print_step(6, "Verify Session Token")
        
        try:
            url = f"{self.server_url}/auth/verify"
            headers = {"Authorization": f"Bearer {self.session_token}"}
            
            self.print_info(f"POST {url}")
            self.print_info(f"Header: Authorization: Bearer {self.session_token[:32]}...")
            
            response = requests.post(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.print_success(f"Session is valid (Status: {response.status_code})")
                self.print_info(f"Response: {data}")
                return True
            else:
                self.print_error(f"Session verification failed (Status: {response.status_code})")
                self.print_info(f"Response: {response.text}")
                return False
                
        except Exception as e:
            self.print_error(f"Verification error: {e}")
            return False
    
    # ========================================================================
    # Run Complete Flow
    # ========================================================================
    def run_complete_flow(self) -> bool:
        """Execute complete authentication flow."""
        print("\n" + "=" * 70)
        print("QUANTUM-RESISTANT AUTHENTICATION CLIENT")
        print("=" * 70)
        print(f"Username:   {self.username}")
        print(f"Server URL: {self.server_url}")
        
        # Step 1: Generate keypair
        if not self.step1_generate_keypair():
            return False
        
        # Step 2: Register
        if not self.step2_register():
            return False
        
        # Step 3: Request nonce
        if not self.step3_request_nonce():
            return False
        
        # Step 4: Sign nonce
        if not self.step4_sign_nonce():
            return False
        
        # Step 5: Login
        if not self.step5_login():
            return False
        
        # Step 6: Verify session
        self.step6_verify_session()
        
        return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    # Parse arguments
    username = sys.argv[1] if len(sys.argv) > 1 else "alice"
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:5000"
    
    # Run client
    client = QuantumAuthClient(username, server_url)
    success = client.run_complete_flow()
    
    # Final result
    print("\n" + "=" * 70)
    if success:
        print("✓✓✓ AUTHENTICATION SUCCESSFUL ✓✓✓")
        print("=" * 70)
        print(f"User '{username}' is now authenticated!")
        print(f"Session Token: {client.session_token}")
        return 0
    else:
        print("✗✗✗ AUTHENTICATION FAILED ✗✗✗")
        print("=" * 70)
        print("Check the errors above and ensure:")
        print("  1. Backend server is running: python backend/app.py")
        print("  2. Server URL is correct")
        print("  3. User not already registered (try different username)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
