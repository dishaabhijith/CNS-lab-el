/**
 * Authentication Flow Management
 * Handles registration, login, and session management
 */

// Configuration
const API_BASE_URL = 'http://localhost:5000';

class AuthManager {
    constructor() {
        this.sessionToken = localStorage.getItem('sessionToken');
        this.username = localStorage.getItem('username');
        this.userId = localStorage.getItem('userId');
        this.privateKey = null; // Never store in localStorage for security
        
        this.setupEventListeners();
        this.checkSession();
    }

    // ========================================================================
    // UI Management
    // ========================================================================

    setupEventListeners() {
        // Registration
        document.getElementById('generateKeysBtn').addEventListener('click', 
            () => this.handleGenerateKeys());
        document.getElementById('registrationForm').addEventListener('submit',
            (e) => this.handleRegister(e));
        document.getElementById('switchToLoginBtn').addEventListener('click',
            () => this.switchToLogin());
        document.getElementById('copyPublicKeyBtn').addEventListener('click',
            () => this.copyToClipboard('publicKeyDisplay'));
        document.getElementById('downloadPrivateKeyBtn').addEventListener('click',
            () => this.downloadPrivateKey());
        document.getElementById('copyPrivateKeyBtn').addEventListener('click',
            () => this.copyToClipboard('privateKeyDisplay'));

        // Login
        document.getElementById('authenticationForm').addEventListener('submit',
            (e) => this.handleLogin(e));
        document.getElementById('switchToRegisterBtn').addEventListener('click',
            () => this.switchToRegister());
        document.getElementById('loadPrivateKeyBtn').addEventListener('click',
            () => document.getElementById('privateKeyFile').click());
        document.getElementById('privateKeyFile').addEventListener('change',
            (e) => this.loadPrivateKeyFromFile(e));

        // Dashboard
        document.getElementById('logoutBtn').addEventListener('click',
            () => this.handleLogout());
    }

    switchToRegister() {
        document.getElementById('registerForm').classList.add('active');
        document.getElementById('loginForm').classList.remove('active');
    }

    switchToLogin() {
        document.getElementById('registerForm').classList.remove('active');
        document.getElementById('loginForm').classList.add('active');
    }

    showStatus(message, type = 'success') {
        const statusEl = document.getElementById('statusMessage');
        const errorEl = document.getElementById('errorMessage');
        
        if (type === 'success') {
            statusEl.textContent = message;
            statusEl.style.display = 'block';
            errorEl.style.display = 'none';
            
            setTimeout(() => {
                statusEl.style.display = 'none';
            }, 5000);
        } else {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
            statusEl.style.display = 'none';
            
            setTimeout(() => {
                errorEl.style.display = 'none';
            }, 5000);
        }
    }

    showDashboard() {
        document.getElementById('authContainer').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        
        document.getElementById('dashboardUsername').textContent = this.username;
        document.getElementById('dashboardUserId').textContent = this.userId;
        document.getElementById('dashboardToken').textContent = 
            this.sessionToken.substring(0, 20) + '...';
        
        // Calculate expiration (typically 24 hours from login)
        const expiresDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
        document.getElementById('dashboardExpires').textContent = 
            expiresDate.toLocaleString();
    }

    showAuthForms() {
        document.getElementById('authContainer').style.display = 'block';
        document.getElementById('dashboard').style.display = 'none';
    }

    // ========================================================================
    // Key Generation
    // ========================================================================

    async handleGenerateKeys() {
        try {
            this.showStatus('Generating quantum-safe key pair...', 'success');
            
            const keyPair = await QuantumCrypto.generateKeyPair();
            this.privateKey = keyPair.privateKey;
            
            // Display keys
            document.getElementById('publicKeyDisplay').value = keyPair.publicKey;
            document.getElementById('privateKeyDisplay').value = keyPair.privateKey;
            
            // Show private key group and buttons
            document.getElementById('privateKeyGroup').style.display = 'block';
            document.getElementById('copyPublicKeyBtn').style.display = 'inline-block';
            document.getElementById('downloadPrivateKeyBtn').style.display = 'inline-block';
            document.getElementById('copyPrivateKeyBtn').style.display = 'inline-block';
            
            // Enable register button
            document.getElementById('registerBtn').disabled = false;
            
            this.showStatus('✓ Key pair generated successfully! Save your private key.', 'success');
        } catch (error) {
            this.showStatus('Error generating keys: ' + error.message, 'error');
        }
    }

    copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        const text = element.value;
        
        navigator.clipboard.writeText(text).then(() => {
            this.showStatus('Copied to clipboard!', 'success');
        }).catch(err => {
            this.showStatus('Failed to copy: ' + err.message, 'error');
        });
    }

    downloadPrivateKey() {
        const privateKey = document.getElementById('privateKeyDisplay').value;
        const username = document.getElementById('regUsername').value;
        
        const keyData = QuantumCrypto.exportKeyPair(
            document.getElementById('publicKeyDisplay').value,
            privateKey
        );
        
        const dataStr = JSON.stringify(keyData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `${username}_keys_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        this.showStatus('Private key downloaded securely', 'success');
    }

    loadPrivateKeyFromFile(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const keyPair = QuantumCrypto.importKeyPair(e.target.result);
                document.getElementById('privateKeyInput').value = keyPair.privateKey;
                this.showStatus('Private key loaded from file', 'success');
            } catch (error) {
                this.showStatus('Error loading key file: ' + error.message, 'error');
            }
        };
        reader.readAsText(file);
    }

    // ========================================================================
    // Registration
    // ========================================================================

    async handleRegister(e) {
        e.preventDefault();
        
        const username = document.getElementById('regUsername').value.trim();
        const publicKey = document.getElementById('publicKeyDisplay').value.trim();
        const privateKey = document.getElementById('privateKeyDisplay').value.trim();
        
        // Validate
        if (!username || !publicKey || !privateKey) {
            this.showStatus('Please generate keys first', 'error');
            return;
        }

        if (!this.validateUsername(username)) {
            this.showStatus('Invalid username format', 'error');
            return;
        }

        try {
            this.showStatus('Registering account...', 'success');
            
            const response = await fetch(`${API_BASE_URL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    public_key: publicKey
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Registration failed');
            }

            this.showStatus('✓ Account registered! You can now login.', 'success');
            
            // Store username for login
            localStorage.setItem('registeredUsername', username);
            localStorage.setItem('registeredPublicKey', publicKey);
            
            // Reset form
            document.getElementById('registrationForm').reset();
            document.getElementById('privateKeyGroup').style.display = 'none';
            document.getElementById('registerBtn').disabled = true;
            
            // Switch to login
            setTimeout(() => this.switchToLogin(), 2000);
        } catch (error) {
            this.showStatus('Registration error: ' + error.message, 'error');
        }
    }

    // ========================================================================
    // Login
    // ========================================================================

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('loginUsername').value.trim();
        const privateKey = document.getElementById('privateKeyInput').value.trim();
        
        // Validate
        if (!username || !privateKey) {
            this.showStatus('Please enter username and private key', 'error');
            return;
        }

        try {
            this.showStatus('Requesting authentication challenge...', 'success');
            
            // Step 1: Request nonce
            const nonceResponse = await fetch(`${API_BASE_URL}/auth/nonce`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username: username })
            });

            const nonceData = await nonceResponse.json();

            if (!nonceResponse.ok) {
                throw new Error(nonceData.error || 'Failed to get nonce');
            }

            this.showStatus('Nonce received, signing with your private key...', 'success');

            // Step 2: Sign the nonce
            const nonce = nonceData.nonce;
            const messageToSign = username + nonce;
            const signature = await QuantumCrypto.signMessage(messageToSign, privateKey);

            this.showStatus('Signature generated, sending for verification...', 'success');

            // Step 3: Login with signature
            const loginResponse = await fetch(`${API_BASE_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    nonce: nonce,
                    signature: signature
                })
            });

            const loginData = await loginResponse.json();

            if (!loginResponse.ok) {
                throw new Error(loginData.error || 'Authentication failed');
            }

            this.showStatus('✓ Authentication successful!', 'success');

            // Store session
            this.sessionToken = loginData.session_token;
            this.username = loginData.username;
            this.userId = loginData.user_id;
            
            localStorage.setItem('sessionToken', this.sessionToken);
            localStorage.setItem('username', this.username);
            localStorage.setItem('userId', this.userId);
            localStorage.setItem('loginTime', new Date().toISOString());

            // Clear login form
            document.getElementById('authenticationForm').reset();
            this.privateKey = null;

            // Show dashboard
            this.showDashboard();
        } catch (error) {
            this.showStatus('Login error: ' + error.message, 'error');
            console.error('Login error:', error);
        }
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    async checkSession() {
        if (!this.sessionToken) {
            this.showAuthForms();
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.sessionToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                this.showDashboard();
            } else {
                // Session expired or invalid
                this.clearSession();
                this.showAuthForms();
            }
        } catch (error) {
            console.error('Session check error:', error);
            this.showAuthForms();
        }
    }

    async handleLogout() {
        try {
            this.showStatus('Logging out...', 'success');
            
            await fetch(`${API_BASE_URL}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.sessionToken}`,
                    'Content-Type': 'application/json'
                }
            });

            this.clearSession();
            this.showAuthForms();
            this.showStatus('✓ Logged out successfully', 'success');
        } catch (error) {
            this.showStatus('Logout error: ' + error.message, 'error');
        }
    }

    clearSession() {
        this.sessionToken = null;
        this.username = null;
        this.userId = null;
        this.privateKey = null;
        
        localStorage.removeItem('sessionToken');
        localStorage.removeItem('username');
        localStorage.removeItem('userId');
        localStorage.removeItem('loginTime');
    }

    // ========================================================================
    // Validation
    // ========================================================================

    validateUsername(username) {
        // Alphanumeric and underscore only, 3-80 characters
        const regex = /^[a-zA-Z0-9_]{3,80}$/;
        return regex.test(username);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    new AuthManager();
});
