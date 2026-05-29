# Production Readiness Notes

This project is still best treated as a research and teaching prototype, but it now includes several production-oriented controls that make the security boundaries clearer.

## Hardened in This Codebase

- CORS is configured from an explicit `CORS_ORIGINS` allowlist instead of a backend wildcard.
- Production startup fails fast when the default development `SECRET_KEY` or wildcard CORS is used.
- API responses receive conservative security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control`, and configurable CSP/HSTS.
- Request body size, public-key size, and signature size are bounded by configuration.
- Authentication routes normalize JSON input and reject non-object or malformed payloads with 400 responses.
- `/auth/nonce` no longer reveals whether a username exists.
- Nonce consumption is performed with a conditional database update so a challenge cannot be reused after either a successful login or a failed signature attempt.
- Session tokens are HMAC-hashed before database storage.
- Frontend session tokens are stored in `sessionStorage`, migrated out of legacy `localStorage`, and hidden from the dashboard.
- Private-key JSON is validated in the browser before requesting a nonce, avoiding accidental one-time slot consumption for obviously bad keys.
- Browser registration now defaults to ML-DSA-65 via `@noble/post-quantum`, and the backend verifies ML-DSA-65 plus SPHINCS+-SHA2-256f via `pqcrypto`.
- Optional session binding to IP and user-agent is available with `BIND_SESSION_TO_IP` and `BIND_SESSION_TO_USER_AGENT`.
- A focused `unittest` suite covers replay rejection, bad signature nonce consumption, generic challenge failures, hashed session storage, oversized input rejection, and security headers.

## Production Environment Checklist

Set these before deploying:

```env
FLASK_ENV=production
SECRET_KEY=<strong unique secret from a secret manager>
DATABASE_URL=postgresql+psycopg://...
CORS_ORIGINS=https://your-frontend.example
SESSION_COOKIE_SECURE=true
HSTS_ENABLED=true
RATELIMIT_STORAGE_URI=redis://...
TRUST_PROXY_HEADERS=true
```

Use a production WSGI server such as Waitress or Gunicorn behind HTTPS. If the app is behind a reverse proxy, configure the proxy to set `X-Forwarded-*` headers correctly before enabling `TRUST_PROXY_HEADERS=true`.

## Still Required Before Real-World Use

- Keep the ML-DSA-65 dependency and key-envelope format under cryptographic review before any real production deployment.
- Use PostgreSQL/MySQL with migrations instead of SQLite and `db.create_all()`.
- Add key rotation, account recovery, device enrollment, device revocation, and account lock/recovery workflows.
- Decide whether bearer tokens are acceptable for your deployment or move to Secure, HttpOnly, SameSite cookies with CSRF protection.
- Run a real threat model, cryptographic review, dependency audit, and penetration test.
- Add CI, dependency scanning, structured logging, metrics, backup/restore procedures, and deployment health checks.
- Add concurrency tests against the production database engine, especially for one-time signature slot allocation and nonce consumption.
