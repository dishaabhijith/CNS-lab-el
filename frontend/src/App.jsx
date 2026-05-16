import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Cpu,
  Download,
  FileKey2,
  Fingerprint,
  KeyRound,
  Loader2,
  LogIn,
  LogOut,
  RefreshCw,
  Server,
  ShieldCheck,
  Upload,
  UserPlus,
  XCircle
} from 'lucide-react';
import { QuantumCrypto } from './lib/quantumCrypto.js';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
const SESSION_KEYS = [
  'sessionToken',
  'username',
  'userId',
  'sessionExpiresAt',
  'algorithm',
  'signatureSlotsRemaining',
  'loginTime'
];

function readSession() {
  const token = sessionStorage.getItem('sessionToken');
  if (!token) return null;
  return {
    token,
    username: sessionStorage.getItem('username') || '',
    userId: sessionStorage.getItem('userId') || '',
    expiresAt: sessionStorage.getItem('sessionExpiresAt') || '',
    algorithm: sessionStorage.getItem('algorithm') || '',
    slotsRemaining: sessionStorage.getItem('signatureSlotsRemaining') || '',
    loginTime: sessionStorage.getItem('loginTime') || ''
  };
}

function writeSession(data) {
  sessionStorage.setItem('sessionToken', data.session_token);
  sessionStorage.setItem('username', data.username);
  sessionStorage.setItem('userId', data.user_id);
  sessionStorage.setItem('sessionExpiresAt', data.expires_at);
  sessionStorage.setItem('algorithm', data.algorithm || '');
  sessionStorage.setItem('signatureSlotsRemaining', data.signature_slots_remaining ?? '');
  sessionStorage.setItem('loginTime', new Date().toISOString());
}

function clearStoredSession() {
  SESSION_KEYS.forEach((key) => {
    sessionStorage.removeItem(key);
    localStorage.removeItem(key);
  });
}

function compact(value, length = 18) {
  if (!value) return 'None';
  if (value.length <= length * 2) return value;
  return `${value.slice(0, length)}...${value.slice(-length)}`;
}

function formatDate(value) {
  if (!value) return 'Not issued';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return 'Unknown';
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
}

function safeJsonSummary(value) {
  try {
    return QuantumCrypto.summarizeJson(value);
  } catch (error) {
    return null;
  }
}

function Button({ children, icon: Icon, variant = 'primary', loading = false, ...props }) {
  return (
    <button className={`button ${variant}`} disabled={loading || props.disabled} {...props}>
      {loading ? <Loader2 className="spin" size={16} /> : Icon ? <Icon size={16} /> : null}
      <span>{children}</span>
    </button>
  );
}

function StatusBanner({ status, onDismiss }) {
  if (!status) return null;
  const Icon = status.type === 'error' ? XCircle : status.type === 'warning' ? AlertTriangle : CheckCircle2;
  return (
    <div className={`status ${status.type}`}>
      <Icon size={18} />
      <span>{status.message}</span>
      <button type="button" onClick={onDismiss} aria-label="Dismiss status">Dismiss</button>
    </div>
  );
}

function Field({ label, value, onChange, placeholder, type = 'text', autoComplete = 'off' }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
      />
    </label>
  );
}

function TextArea({ label, value, onChange, placeholder, readOnly = false, rows = 7 }) {
  return (
    <label className="field">
      <span>{label}</span>
      <textarea
        value={value}
        onChange={(event) => onChange?.(event.target.value)}
        placeholder={placeholder}
        readOnly={readOnly}
        rows={rows}
      />
    </label>
  );
}

function Metric({ icon: Icon, label, value, tone = 'neutral' }) {
  return (
    <div className={`metric ${tone}`}>
      <Icon size={18} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function KeyValue({ label, value, mono = false }) {
  return (
    <div className="kv">
      <span>{label}</span>
      <strong className={mono ? 'mono' : ''}>{value ?? 'None'}</strong>
    </div>
  );
}

function SegmentTabs({ mode, setMode, hasSession }) {
  const items = [
    { id: 'register', label: 'Register', icon: UserPlus },
    { id: 'login', label: 'Login', icon: LogIn },
    { id: 'dashboard', label: 'Session', icon: ShieldCheck, disabled: !hasSession }
  ];
  return (
    <div className="segments">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            type="button"
            className={mode === item.id ? 'active' : ''}
            disabled={item.disabled}
            onClick={() => setMode(item.id)}
          >
            <Icon size={15} />
            <span>{item.label}</span>
          </button>
        );
      })}
    </div>
  );
}

function RuntimePanel({ health, algorithms, onRefresh, loading }) {
  const supported = algorithms?.supported_algorithms || [];
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Runtime</p>
          <h2>System Surface</h2>
        </div>
        <button className="icon-button" type="button" onClick={onRefresh} aria-label="Refresh runtime status">
          {loading ? <Loader2 className="spin" size={17} /> : <RefreshCw size={17} />}
        </button>
      </div>

      <div className="metric-grid">
        <Metric
          icon={Server}
          label="Backend"
          value={health?.status === 'ok' ? 'Online' : 'Offline'}
          tone={health?.status === 'ok' ? 'good' : 'bad'}
        />
        <Metric
          icon={Cpu}
          label="Backend PQC"
          value={algorithms?.best_installed_backend || 'Unknown'}
          tone="info"
        />
        <Metric
          icon={Activity}
          label="Nonce TTL"
          value={formatDuration(algorithms?.nonce_expires_in_seconds)}
          tone="warn"
        />
        <Metric
          icon={Fingerprint}
          label="Browser Default"
          value={algorithms?.default_algorithm || QuantumCrypto.WOTS_ALGORITHM}
          tone="neutral"
        />
      </div>

      <div className="algorithm-list">
        {supported.map((algorithm) => (
          <div className="algorithm-row" key={algorithm.name}>
            <div>
              <strong>{algorithm.name}</strong>
              <span>{algorithm.type}</span>
            </div>
            <div className="badges">
              <span className={algorithm.available ? 'badge good' : 'badge muted'}>
                {algorithm.available ? 'available' : 'not installed'}
              </span>
              {algorithm.browser_supported ? <span className="badge info">browser</span> : null}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function TracePanel({ traces }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Network</p>
          <h2>API Activity</h2>
        </div>
      </div>
      <div className="trace-list">
        {traces.length === 0 ? (
          <div className="empty">No API calls yet.</div>
        ) : traces.map((trace) => (
          <div className="trace-row" key={trace.id}>
            <span className={`dot ${trace.ok ? 'good' : 'bad'}`} />
            <strong>{trace.method}</strong>
            <span className="mono">{trace.path}</span>
            <span>{trace.status}</span>
            <span>{trace.ms}ms</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ChallengePanel({ challenge, signature, keyInfo }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Challenge</p>
          <h2>Nonce and Signature</h2>
        </div>
      </div>
      <div className="kv-stack">
        <KeyValue label="Nonce" value={compact(challenge?.nonce, 16)} mono />
        <KeyValue label="Nonce ID" value={compact(challenge?.nonce_id, 10)} mono />
        <KeyValue label="Key slot" value={challenge?.key_index ?? 'Not assigned'} />
        <KeyValue label="Remaining slots" value={challenge?.signature_slots_remaining ?? 'Unknown'} />
        <KeyValue label="Private key slots" value={keyInfo?.slots ?? 'Not loaded'} />
        <KeyValue label="Signature" value={compact(signature, 14)} mono />
      </div>
    </section>
  );
}

function RegisterView({
  username,
  setUsername,
  slotCount,
  setSlotCount,
  generated,
  generating,
  registering,
  onGenerate,
  onRegister,
  onCopy,
  onDownload
}) {
  const publicSummary = safeJsonSummary(generated?.publicKey);
  const privateSummary = safeJsonSummary(generated?.privateKey);

  return (
    <div className="view-grid">
      <div className="form-block">
        <Field
          label="Username"
          value={username}
          onChange={setUsername}
          placeholder="alice_research"
        />
        <label className="field">
          <span>One-time signature slots</span>
          <input
            type="number"
            min="1"
            max="64"
            value={slotCount}
            onChange={(event) => setSlotCount(event.target.value)}
          />
        </label>
        <div className="button-row">
          <Button icon={KeyRound} variant="secondary" loading={generating} onClick={onGenerate}>
            Generate keys
          </Button>
          <Button icon={UserPlus} loading={registering} disabled={!generated?.publicKey} onClick={onRegister}>
            Register public key
          </Button>
        </div>
      </div>

      <div className="key-grid">
        <div className="key-pane">
          <div className="pane-head">
            <div>
              <p className="eyebrow">Public material</p>
              <h3>Server Record</h3>
            </div>
            <button className="icon-button" type="button" onClick={() => onCopy(generated?.publicKey)} disabled={!generated?.publicKey} aria-label="Copy public key">
              <Clipboard size={16} />
            </button>
          </div>
          <TextArea label="Public key JSON" value={generated?.publicKey || ''} readOnly placeholder="Generated public key" rows={8} />
          <div className="summary-row">
            <span>{publicSummary?.algorithm || 'No key'}</span>
            <span>{publicSummary?.slots ?? 0} slots</span>
            <span>{publicSummary?.chars ?? 0} chars</span>
          </div>
        </div>

        <div className="key-pane secret">
          <div className="pane-head">
            <div>
              <p className="eyebrow">Private material</p>
              <h3>Client Secret</h3>
            </div>
            <div className="icon-pair">
              <button className="icon-button" type="button" onClick={() => onCopy(generated?.privateKey)} disabled={!generated?.privateKey} aria-label="Copy private key">
                <Clipboard size={16} />
              </button>
              <button className="icon-button" type="button" onClick={onDownload} disabled={!generated?.privateKey} aria-label="Download private key">
                <Download size={16} />
              </button>
            </div>
          </div>
          <TextArea label="Private key JSON" value={generated?.privateKey || ''} readOnly placeholder="Generated private key" rows={8} />
          <div className="summary-row">
            <span>{privateSummary?.algorithm || 'No key'}</span>
            <span>{privateSummary?.slots ?? 0} slots</span>
            <span>{privateSummary?.chars ?? 0} chars</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function LoginView({
  username,
  setUsername,
  privateKey,
  setPrivateKey,
  privateKeyInfo,
  onLoadFile,
  fileRef,
  onLogin,
  authenticating
}) {
  return (
    <div className="view-grid login-grid">
      <div className="form-block">
        <Field
          label="Username"
          value={username}
          onChange={setUsername}
          placeholder="alice_research"
        />
        <TextArea
          label="Private key"
          value={privateKey}
          onChange={setPrivateKey}
          placeholder="Paste or load your private key JSON"
          rows={11}
        />
        <input
          ref={fileRef}
          className="hidden-file"
          type="file"
          accept=".json,.key,.txt"
          onChange={onLoadFile}
        />
        <div className="button-row">
          <Button icon={Upload} variant="secondary" onClick={() => fileRef.current?.click()}>
            Load key file
          </Button>
          <Button icon={LogIn} loading={authenticating} onClick={onLogin}>
            Authenticate
          </Button>
        </div>
      </div>

      <div className="key-pane">
        <div className="pane-head">
          <div>
            <p className="eyebrow">Client key</p>
            <h3>Loaded Bundle</h3>
          </div>
          <FileKey2 size={20} />
        </div>
        <div className="kv-stack">
          <KeyValue label="Algorithm" value={privateKeyInfo?.algorithm || 'Not loaded'} />
          <KeyValue label="Slots" value={privateKeyInfo?.slots ?? 'Not loaded'} />
          <KeyValue label="Private bytes" value={privateKeyInfo?.bytes ?? 'Not loaded'} />
          <KeyValue label="Storage" value="Browser memory only" />
        </div>
      </div>
    </div>
  );
}

function DashboardView({ session, userInfo, onVerify, onUserInfo, onLogout, verifying }) {
  return (
    <div className="dashboard-grid">
      <div className="session-board">
        <div className="identity-mark">
          <ShieldCheck size={28} />
          <div>
            <p className="eyebrow">Authenticated identity</p>
            <h3>{session?.username || 'No active session'}</h3>
          </div>
        </div>
        <div className="kv-stack">
          <KeyValue label="User ID" value={compact(session?.userId, 14)} mono />
          <KeyValue label="Token" value={session?.token ? 'Active and hidden' : 'None'} />
          <KeyValue label="Expires" value={formatDate(session?.expiresAt)} />
          <KeyValue label="Algorithm" value={session?.algorithm || 'Unknown'} />
          <KeyValue label="Slots remaining" value={session?.slotsRemaining || 'Unknown'} />
        </div>
        <div className="button-row">
          <Button icon={RefreshCw} variant="secondary" loading={verifying} onClick={onVerify}>
            Verify session
          </Button>
          <Button icon={Fingerprint} variant="secondary" onClick={onUserInfo}>
            Fetch user
          </Button>
          <Button icon={LogOut} variant="danger" onClick={onLogout}>
            Logout
          </Button>
        </div>
      </div>

      <div className="key-pane">
        <div className="pane-head">
          <div>
            <p className="eyebrow">User endpoint</p>
            <h3>Account Record</h3>
          </div>
          <Server size={20} />
        </div>
        <pre className="json-box">{userInfo ? JSON.stringify(userInfo, null, 2) : 'No /auth/user response yet.'}</pre>
      </div>
    </div>
  );
}

function FlowPanel({ session, challenge, signature }) {
  const steps = [
    { label: 'Key bundle generated', active: true },
    { label: 'Public key registered', active: Boolean(localStorage.getItem('registeredUsername')) },
    { label: 'Nonce issued', active: Boolean(challenge?.nonce) },
    { label: 'Signature produced', active: Boolean(signature) },
    { label: 'Session issued', active: Boolean(session?.token) }
  ];
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Protocol</p>
          <h2>Auth Flow</h2>
        </div>
      </div>
      <div className="flow-list">
        {steps.map((step, index) => (
          <div className={`flow-step ${step.active ? 'active' : ''}`} key={step.label}>
            <span>{index + 1}</span>
            <strong>{step.label}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export function App() {
  const fileRef = useRef(null);
  const [mode, setMode] = useState(readSession() ? 'dashboard' : 'register');
  const [status, setStatus] = useState(null);
  const [health, setHealth] = useState(null);
  const [algorithms, setAlgorithms] = useState(null);
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [traces, setTraces] = useState([]);
  const [session, setSession] = useState(readSession());
  const [userInfo, setUserInfo] = useState(null);

  const [regUsername, setRegUsername] = useState(localStorage.getItem('registeredUsername') || '');
  const [slotCount, setSlotCount] = useState('16');
  const [generated, setGenerated] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [registering, setRegistering] = useState(false);

  const [loginUsername, setLoginUsername] = useState(localStorage.getItem('registeredUsername') || '');
  const [privateKey, setPrivateKey] = useState('');
  const [authenticating, setAuthenticating] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [challenge, setChallenge] = useState(null);
  const [signature, setSignature] = useState('');

  const privateKeyInfo = useMemo(() => {
    if (!privateKey.trim()) return null;
    try {
      return QuantumCrypto.getPrivateKeyInfo(privateKey.trim());
    } catch (error) {
      return null;
    }
  }, [privateKey]);

  const pushTrace = (trace) => {
    setTraces((current) => [trace, ...current].slice(0, 8));
  };

  const api = async (path, options = {}) => {
    const method = options.method || 'GET';
    const started = performance.now();
    let response;
    let payload;
    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        method,
        cache: 'no-store',
        headers: {
          ...(options.body ? { 'Content-Type': 'application/json' } : {}),
          ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
          ...(options.headers || {})
        },
        body: options.body ? JSON.stringify(options.body) : undefined
      });

      const text = await response.text();
      payload = text ? JSON.parse(text) : {};
      pushTrace({
        id: `${Date.now()}-${Math.random()}`,
        method,
        path,
        status: response.status,
        ok: response.ok,
        ms: Math.round(performance.now() - started)
      });
    } catch (error) {
      pushTrace({
        id: `${Date.now()}-${Math.random()}`,
        method,
        path,
        status: 'ERR',
        ok: false,
        ms: Math.round(performance.now() - started)
      });
      throw error;
    }

    if (!response.ok) {
      throw new Error(payload?.error || `Request failed with ${response.status}`);
    }
    return payload;
  };

  const refreshRuntime = async () => {
    setRuntimeLoading(true);
    try {
      const [healthData, algorithmData] = await Promise.all([
        api('/health'),
        api('/auth/algorithms')
      ]);
      setHealth(healthData);
      setAlgorithms(algorithmData);
    } catch (error) {
      setHealth(null);
      setStatus({ type: 'warning', message: `Backend status unavailable: ${error.message}` });
    } finally {
      setRuntimeLoading(false);
    }
  };

  const verifySession = async (token = session?.token) => {
    if (!token) return null;
    setVerifying(true);
    try {
      const data = await api('/auth/verify', { method: 'POST', token });
      const updated = {
        token,
        username: data.username,
        userId: data.user_id,
        expiresAt: data.expires_at,
        algorithm: data.algorithm,
        slotsRemaining: data.signature_slots_remaining ?? '',
        loginTime: sessionStorage.getItem('loginTime') || ''
      };
      setSession(updated);
      sessionStorage.setItem('sessionExpiresAt', updated.expiresAt);
      sessionStorage.setItem('algorithm', updated.algorithm || '');
      sessionStorage.setItem('signatureSlotsRemaining', updated.slotsRemaining);
      return updated;
    } catch (error) {
      clearStoredSession();
      setSession(null);
      setMode('login');
      setStatus({ type: 'warning', message: 'Stored session is no longer valid.' });
      return null;
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    const legacyToken = localStorage.getItem('sessionToken');
    if (legacyToken && !sessionStorage.getItem('sessionToken')) {
      SESSION_KEYS.forEach((key) => {
        const value = localStorage.getItem(key);
        if (value !== null) sessionStorage.setItem(key, value);
        localStorage.removeItem(key);
      });
      setSession(readSession());
    }

    refreshRuntime();
    const currentSession = readSession();
    if (currentSession?.token) verifySession(currentSession.token);
  }, []);

  const showSuccess = (message) => setStatus({ type: 'success', message });
  const showError = (message) => setStatus({ type: 'error', message });

  const handleGenerate = async () => {
    const slots = Number(slotCount);
    if (!Number.isInteger(slots) || slots < 1 || slots > 64) {
      showError('Signature slots must be between 1 and 64.');
      return;
    }

    setGenerating(true);
    try {
      const keys = await QuantumCrypto.generateKeyPair(slots);
      setGenerated(keys);
      setSignature('');
      setChallenge(null);
      showSuccess(`Generated ${keys.algorithm} bundle with ${keys.signatureSlots} one-time slots.`);
    } catch (error) {
      showError(error.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleRegister = async () => {
    if (!regUsername.trim() || !generated?.publicKey) {
      showError('Username and public key are required.');
      return;
    }

    setRegistering(true);
    try {
      const data = await api('/auth/register', {
        method: 'POST',
        body: {
          username: regUsername.trim(),
          public_key: generated.publicKey,
          algorithm: generated.algorithm
        }
      });
      localStorage.setItem('registeredUsername', data.username);
      localStorage.setItem('registeredPublicKey', generated.publicKey);
      localStorage.setItem('registeredAlgorithm', data.algorithm);
      setLoginUsername(data.username);
      setMode('login');
      showSuccess(`Registered ${data.username} with ${data.algorithm}.`);
    } catch (error) {
      showError(error.message);
    } finally {
      setRegistering(false);
    }
  };

  const handleLogin = async () => {
    if (!loginUsername.trim() || !privateKey.trim()) {
      showError('Username and private key are required.');
      return;
    }

    let keyInfo;
    try {
      keyInfo = QuantumCrypto.getPrivateKeyInfo(privateKey.trim());
    } catch (error) {
      showError(error.message);
      return;
    }

    setAuthenticating(true);
    try {
      const nonceData = await api('/auth/nonce', {
        method: 'POST',
        body: { username: loginUsername.trim() }
      });
      setChallenge(nonceData);

      const keyIndex = nonceData.key_index ?? 0;
      if (keyIndex >= keyInfo.slots) {
        throw new Error('Private key does not contain the requested one-time signature slot.');
      }

      const message = `${loginUsername.trim()}${nonceData.nonce}`;
      const signed = await QuantumCrypto.signMessage(message, privateKey.trim(), keyIndex);
      setSignature(signed);

      const loginData = await api('/auth/login', {
        method: 'POST',
        body: {
          username: loginUsername.trim(),
          nonce: nonceData.nonce,
          signature: signed
        }
      });

      writeSession(loginData);
      setSession(readSession());
      setPrivateKey('');
      setMode('dashboard');
      showSuccess(`Authenticated as ${loginData.username}.`);
      refreshRuntime();
    } catch (error) {
      showError(error.message);
    } finally {
      setAuthenticating(false);
    }
  };

  const handleLoadFile = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const imported = QuantumCrypto.importKeyPair(reader.result);
        setPrivateKey(imported.privateKey);
        showSuccess('Private key file loaded.');
      } catch (error) {
        showError(error.message);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const handleCopy = async (value) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      showSuccess('Copied to clipboard.');
    } catch (error) {
      showError('Clipboard access failed.');
    }
  };

  const handleDownload = () => {
    if (!generated?.privateKey) return;
    const payload = QuantumCrypto.exportKeyPair(generated.publicKey, generated.privateKey);
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${regUsername || 'quantum-auth'}-private-key.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showSuccess('Private key bundle downloaded.');
  };

  const handleUserInfo = async () => {
    if (!session?.token) return;
    try {
      const data = await api('/auth/user', { token: session.token });
      setUserInfo(data);
      showSuccess('User record refreshed.');
    } catch (error) {
      showError(error.message);
    }
  };

  const handleLogout = async () => {
    if (session?.token) {
      try {
        await api('/auth/logout', { method: 'POST', token: session.token });
      } catch (error) {
        // Local cleanup still happens for expired sessions.
      }
    }
    clearStoredSession();
    setSession(null);
    setUserInfo(null);
    setMode('login');
    showSuccess('Session closed.');
  };

  const registeredName = localStorage.getItem('registeredUsername');

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={24} />
          </div>
          <div>
            <p className="eyebrow">Quantum Auth Console</p>
            <h1>Passwordless PQC Authentication</h1>
          </div>
        </div>
        <div className="topbar-actions">
          <span className={`connection ${health?.status === 'ok' ? 'online' : 'offline'}`}>
            {health?.status === 'ok' ? 'Backend online' : 'Backend offline'}
          </span>
          <Button icon={RefreshCw} variant="ghost" loading={runtimeLoading} onClick={refreshRuntime}>
            Refresh
          </Button>
        </div>
      </header>

      <main className="layout">
        <section className="workbench">
          <div className="workbench-head">
            <div>
              <p className="eyebrow">Workspace</p>
              <h2>{mode === 'register' ? 'Register Key Bundle' : mode === 'login' ? 'Challenge Login' : 'Session Dashboard'}</h2>
            </div>
            <SegmentTabs mode={mode} setMode={setMode} hasSession={Boolean(session?.token)} />
          </div>

          <StatusBanner status={status} onDismiss={() => setStatus(null)} />

          {mode === 'register' ? (
            <RegisterView
              username={regUsername}
              setUsername={setRegUsername}
              slotCount={slotCount}
              setSlotCount={setSlotCount}
              generated={generated}
              generating={generating}
              registering={registering}
              onGenerate={handleGenerate}
              onRegister={handleRegister}
              onCopy={handleCopy}
              onDownload={handleDownload}
            />
          ) : null}

          {mode === 'login' ? (
            <LoginView
              username={loginUsername}
              setUsername={setLoginUsername}
              privateKey={privateKey}
              setPrivateKey={setPrivateKey}
              privateKeyInfo={privateKeyInfo}
              onLoadFile={handleLoadFile}
              fileRef={fileRef}
              onLogin={handleLogin}
              authenticating={authenticating}
            />
          ) : null}

          {mode === 'dashboard' ? (
            <DashboardView
              session={session}
              userInfo={userInfo}
              onVerify={() => verifySession()}
              onUserInfo={handleUserInfo}
              onLogout={handleLogout}
              verifying={verifying}
            />
          ) : null}
        </section>

        <aside className="side-stack">
          <RuntimePanel
            health={health}
            algorithms={algorithms}
            onRefresh={refreshRuntime}
            loading={runtimeLoading}
          />
          <ChallengePanel challenge={challenge} signature={signature} keyInfo={privateKeyInfo} />
          <FlowPanel session={session} challenge={challenge} signature={signature} />
          <TracePanel traces={traces} />
          <section className="panel compact-panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Local state</p>
                <h2>Browser Vault</h2>
              </div>
              <KeyRound size={18} />
            </div>
            <div className="kv-stack">
              <KeyValue label="Registered user" value={registeredName || 'None'} />
              <KeyValue label="Session store" value={session?.token ? 'sessionStorage' : 'Empty'} />
              <KeyValue label="API base" value={API_BASE_URL || 'Vite proxy'} />
            </div>
          </section>
        </aside>
      </main>
    </div>
  );
}
