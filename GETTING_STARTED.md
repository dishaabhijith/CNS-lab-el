# Getting Started Guide

## Step-by-Step Setup Instructions

### Step 1: Install Python

Make sure you have Python 3.8 or later installed.

```bash
python --version
```

If not installed, download from [python.org](https://www.python.org/downloads/)

### Step 2: Clone/Download Project

```bash
# If this is a git repository:
git clone <repository-url>
cd quantum-auth-system

# Or if downloaded as zip:
# Extract to a folder and navigate to it
cd quantum-auth-system
```

### Step 3: Set Up Backend

#### 3a. Create Virtual Environment

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt after activation.

#### 3b. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- Flask (web framework)
- Flask-CORS (cross-origin requests)
- SQLAlchemy (database ORM)
- cryptography (crypto utilities)

#### 3c. Create Environment File (Optional)

```bash
# Copy example config
cp ..\.env.example .env  # Windows
cp ../.env.example .env  # macOS/Linux

# Edit .env if needed (usually not required for dev)
```

#### 3d. Run Backend Server

```bash
python app.py
```

You should see:
```
WARNING: This is a development server. Do not use it in production.
Running on http://127.0.0.1:5000
```

**Keep this terminal window open!**

### Step 4: Set Up Frontend

Open a **new terminal window** (keep backend running in the first):

```bash
# Navigate to project root (not backend)
cd ..

# Start a local web server
# Using Python 3:
python -m http.server 8000

# Or using Node.js (if installed):
npx http-server -p 8000
```

You should see:
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```

### Step 5: Access the Application

Open your web browser and go to:

```
http://localhost:8000/frontend/index.html
```

You should see the quantum-resistant authentication interface! 🎉

## Testing the System

### Test Flow 1: Complete Registration & Login

1. **Go to the Registration tab** (should be active by default)

2. **Generate Keys**:
   - Click "Generate Quantum-Safe Key Pair"
   - Wait for keys to appear in the text areas
   - Public key and private key will be displayed

3. **Save Your Private Key**:
   - Click "Download Private Key" to save it securely
   - Or click "Copy to Clipboard" to copy manually

4. **Create Account**:
   - Enter a username (e.g., `alice`)
   - Click "Register"
   - You should see "Account registered!" message

5. **Switch to Login Tab**:
   - Click "Already have an account? Login"
   - Or reload the page to clear the registration form

6. **Login**:
   - Enter your username
   - Paste your private key in the text area
   - Click "Login with Digital Signature"
   - System will:
     - Request nonce from server
     - Sign it with your private key
     - Send signature for verification
   - If successful, you'll see the Dashboard

7. **View Dashboard**:
   - See session information
   - Learn how the authentication works
   - Click "Logout" to end session

### Test Flow 2: Wrong Private Key (Should Fail)

1. Try logging in with an incorrect private key
2. Should see error message
3. System will not authenticate

### Test Flow 3: Multiple Users

1. Register with username `bob`
2. Generate new keys for `bob`
3. Register `bob`
4. Logout (or use different browser/private window)
5. Register with username `charlie`
6. Generate new keys for `charlie`
7. Register `charlie`
8. Login with `charlie`
9. Logout and login with `bob`

### Test Flow 4: Rate Limiting

1. Try logging in with wrong key 5 times
2. On the 6th attempt, should see "Too many attempts" error

## Checking Backend API Directly

You can test the API endpoints using curl or Postman:

### 1. Register User

```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","public_key":"abc123def456...abc123def456...abc123def456ab"}'
```

### 2. Get Nonce

```bash
curl -X POST http://localhost:5000/auth/nonce \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser"}'
```

### 3. Health Check

```bash
curl http://localhost:5000/health
```

## Understanding What Happens

### When You Register:

1. Browser generates XMSS key pair locally
2. Public key is sent to server
3. Server stores public key in database (never the private key!)
4. Private key stays on your computer

### When You Login:

1. You enter username and private key
2. Browser requests a nonce (one-time random number) from server
3. Browser signs `username + nonce` with your private key
4. Browser sends signature to server
5. Server verifies signature using your stored public key
6. If valid, server creates a session
7. Session token is returned to browser
8. Browser stores session token locally

### Why This is Secure:

- **No passwords**: Server never knows your private key
- **No replay attacks**: Each nonce is used only once
- **Quantum-safe**: XMSS is resistant to quantum computers
- **Proof of identity**: Only holder of private key can create valid signature

## Troubleshooting

### Backend won't start

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Make sure venv is activated (you should see (venv) in terminal)
# Then reinstall:
pip install -r requirements.txt
```

### Frontend can't connect to backend

**Error**: CORS error in browser console

**Solution**:
- Make sure backend is running on `http://localhost:5000`
- Check backend terminal for error messages
- Try visiting `http://localhost:5000/health` in browser to verify backend is running

### Can't access frontend

**Error**: Can't access `http://localhost:8000`

**Solution**:
- Make sure you started the web server (Step 4)
- Check the terminal running the web server
- Try visiting `http://localhost:8000` without the `/frontend/index.html` to verify server is running

### Database errors

**Error**: `sqlite3.OperationalError`

**Solution**:
- Backend creates database automatically
- If issues persist, delete `quantum_auth.db` in the backend folder:
  ```bash
  rm quantum_auth.db  # macOS/Linux
  del quantum_auth.db # Windows
  ```
- Restart backend (it will recreate the database)

### Lost private key

**Problem**: You registered but forgot to save your private key

**Solution**:
- You'll need to register again with a different username
- Always save/download your private key after generation!
- In production, implement key recovery or backup options

## Monitoring Backend

The backend logs important events. Check the terminal running the Flask app for:

- Registration events
- Login attempts
- Failed authentications
- Session creation/expiration

Example log output:
```
2024-01-15 10:30:45 - INFO - Quantum-Resistant Authentication System started
2024-01-15 10:31:02 - INFO - User 'alice' registered successfully
2024-01-15 10:31:15 - INFO - Login successful for user 'alice'
```

## Next Steps

Once you've tested the system:

1. **Read the ARCHITECTURE.md** for deep dive into design
2. **Explore the code** to understand how it works
3. **Try modifying it** (add features, improve security, etc.)
4. **Deploy to production** (add HTTPS, use PostgreSQL, etc.)
5. **Write tests** to ensure everything works

## Project Timeline

- **Phase 1** (Now): Understanding the system - 30 minutes
- **Phase 2**: Exploring the code - 1-2 hours
- **Phase 3**: Making modifications - 2-4 hours
- **Phase 4**: Adding new features - 4+ hours

## Useful Resources

### Within This Project:
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design details
- [README.md](README.md) - Project overview
- [backend/app.py](backend/app.py) - Flask application code
- [backend/auth_routes.py](backend/auth_routes.py) - API endpoints
- [backend/crypto_utils.py](backend/crypto_utils.py) - Cryptographic operations
- [frontend/js/auth.js](frontend/js/auth.js) - Frontend authentication logic
- [frontend/js/crypto.js](frontend/js/crypto.js) - Client-side cryptography

### External:
- [XMSS Specification](https://tools.ietf.org/html/rfc8391)
- [Post-Quantum Cryptography (NIST)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)

## Support

If you encounter issues:

1. **Check the error message** - usually very helpful
2. **Check the browser console** - F12 or Right-click → Inspect → Console
3. **Check backend terminal** - shows server-side errors
4. **Restart both servers** - sometimes fixes temporary issues
5. **Clear browser cache** - Ctrl+Shift+Delete (or Cmd+Shift+Delete on Mac)

---

Happy learning! 🚀

Have fun exploring quantum-resistant cryptography! 🔐
