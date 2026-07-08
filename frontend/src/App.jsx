import { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
/* ---------------------------------------------------------------- */
/* Icons & Constants                                                */
/* ---------------------------------------------------------------- */
function IconRadar({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}><circle cx="12" cy="12" r="9" strokeOpacity="0.9" /><circle cx="12" cy="12" r="5" strokeOpacity="0.5" /><path d="M12 12V4" strokeLinecap="round" /><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" /></svg>; }
function IconBracket({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M9 18 5 12 9 6" /><path d="M15 6l4 6-4 6" /></svg>; }
function IconShieldCheck({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M12 3l7 3v6c0 5-3.2 7.8-7 9-3.8-1.2-7-4-7-9V6z" /><path d="M9 12.2l2 2 4-4.4" /></svg>; }
function IconBug({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M9 7V5a3 3 0 0 1 6 0v2" /><rect x="6" y="7" width="12" height="11" rx="5.5" /><path d="M6 12H3M21 12h-3M8 4 6 2M16 4l2-2M9 18l-2 2M15 18l2 2" /></svg>; }
function IconTarget({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="0.8" fill="currentColor" stroke="none" /><path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3" strokeLinecap="round" /></svg>; }

const NAV_LINKS = [{ href: "#capabilities", label: "Capabilities" }, { href: "#demo", label: "Live demo" }, { href: "#", label: "Docs" }];
const FEATURES = [
  { n: "01", cmd: "itek recon --target acme.io", title: "Recon", desc: "Map subdomains, DNS records, open ports, and service fingerprints before touching an endpoint.", icon: IconRadar },
  { n: "02", cmd: "itek inject --engine sqlmap+", title: "SQL Injection", desc: "Boolean, time-based, and union-based injection testing across every form parameters and API field.", icon: IconBracket },
  { n: "03", cmd: "itek match --cve-db nightly", title: "CVE Detection", desc: "Cross-reference fingerprinted targets against a nightly-updated feed to isolate exploitable versions.", icon: IconShieldCheck },
  { n: "04", cmd: "itek DAST --crawl-depth 5", title: "DAST Engine", desc: "Crawl and fuzz operational infrastructure workflows for authentication bypasses, XSS, and IDOR vulnerabilities.", icon: IconBug },
  { n: "05", cmd: "itek exploit --confirm-only", title: "Exploitation Matrix", desc: "Verify active vectors with secure confirm-only payloads to eliminate false positives cleanly.", icon: IconTarget },
];
const SCAN_LINES = [
  { type: "cmd", text: "itek scan --target acme-corp.io --mode full" },
  { type: "log", text: "[00:01] resolving subdomains ......... 214 found" },
  { type: "log", text: "[00:04] probing open ports ........... 1,882 open / 214 hosts" },
  { type: "critical", text: "CVE-2021-41773 — Apache 2.4.49 path traversal, RCE confirmed" },
  { type: "done", text: "4 confirmed findings — report ready" },
];

/* ---------------------------------------------------------------- */
/* Base UI (Navbar, Hero, Capabilities, Demo, Auth)                 */
/* ---------------------------------------------------------------- */
function Navbar({ setView, view }) {
  const handleNavClick = (v) => setView(v);
  return (
    <nav className="fixed inset-x-0 top-0 z-50 border-b border-white/10 bg-black/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <button onClick={() => handleNavClick(localStorage.getItem("itek_user") ? "dashboard" : "landing")} className="flex items-center gap-2.5 bg-transparent border-none cursor-pointer">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-400 font-mono font-bold text-black">I</span>
          <span className="font-mono text-lg font-bold text-white">ITEK</span>
        </button>
        {view !== "dashboard" && (
          <div className="hidden items-center gap-3 md:flex">
            <button onClick={() => handleNavClick("login")} className="text-sm font-medium text-gray-300 hover:text-white bg-transparent border-none cursor-pointer">Log in</button>
            <button onClick={() => handleNavClick("signup")} className="rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-sm font-semibold text-black cursor-pointer">Sign up</button>
          </div>
        )}
      </div>
    </nav>
  );
}

function Hero({ setView }) {
  return (
    <section className="relative overflow-hidden px-6 pb-24 pt-40 text-center">
      <h1 className="mt-8 font-mono text-5xl font-bold text-white sm:text-6xl lg:text-7xl">Attack your own<br /><span className="bg-gradient-to-r from-emerald-300 to-cyan-400 bg-clip-text text-transparent">infrastructure first.</span></h1>
      <div className="mt-10"><button onClick={() => setView("signup")} className="rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-8 py-3.5 text-sm font-semibold text-black cursor-pointer">Start an assessment</button></div>
    </section>
  );
}

function Capabilities() { 
  return (
    <section className="mx-auto max-w-7xl px-6 py-24 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
      {FEATURES.map((f) => {
        const IconComponent = f.icon; 
        return (
          <div key={f.n} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6">
            <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400"><IconComponent className="h-5 w-5" /></div>
            <h3 className="mb-2 text-lg font-semibold text-white">{f.title}</h3>
            <p className="text-sm text-gray-400">{f.desc}</p>
          </div>
        );
      })}
    </section>
  ); 
}

function TerminalDemo() { 
  return (
    <section className="px-6 py-24">
      <div className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-white/10 bg-zinc-950/80 p-6 font-mono text-sm">
        {SCAN_LINES.map((line, i) => (
          <p key={i} className={line.type === "cmd" ? "text-gray-200" : line.type === "critical" ? "text-red-400" : "text-gray-500"}>{line.text}</p>
        ))}
      </div>
    </section>
  ); 
}

function AuthPage({ view, setView, onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [needsVerification, setNeedsVerification] = useState(false);
  const [signupDone, setSignupDone] = useState(false);
  const [resendStatus, setResendStatus] = useState(null);
  const [resendCountdown, setResendCountdown] = useState(0);

  // Countdown timer for resend button
  useEffect(() => {
    if (resendCountdown <= 0) return;
    const timer = setTimeout(() => setResendCountdown(resendCountdown - 1), 1000);
    return () => clearTimeout(timer);
  }, [resendCountdown]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setNeedsVerification(false);
    try {
      const endpoint = view === "login" ? "/login" : "/signup";
      const payload = view === "login" ? { email, password } : { email, username, password };
      const res = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        // 403 on /login means the account exists but the email hasn't been
        // verified yet -- offer a resend instead of just showing an error.
        if (view === "login" && res.status === 403) setNeedsVerification(true);
        throw new Error(data.detail);
      }
      if (view === "login") onLoginSuccess(data.username); else setSignupDone(true);
    } catch (err) { setError(err.message); }
  };

  const handleResend = async () => {
    setResendStatus("sending");
    setResendCountdown(30);
    try {
      await fetch(`${API_BASE_URL}/resend-verification`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }),
      });
      setResendStatus("sent");
    } catch { setResendStatus("error"); }
  };

  if (signupDone) {
    return (
      <section className="flex min-h-screen items-center justify-center px-6">
        <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950 p-8 text-center">
          <h2 className="text-lg font-semibold text-white mb-2">Check your email</h2>
          <p className="text-sm text-gray-400 mb-6">We sent a verification link to <span className="text-gray-200">{email}</span>. Click it to verify your email and activate your account.</p>
          <button onClick={() => { setSignupDone(false); setView("login"); }} className="w-full bg-emerald-400 text-black font-bold p-3 rounded cursor-pointer">GO TO LOGIN</button>
        </div>
      </section>
    );
  }

  return (
    <section className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950 p-8">
        <form onSubmit={handleSubmit} className="space-y-5">
          {error && <p className="text-red-400 text-xs text-center">{error}</p>}
          {view === "signup" && <input placeholder="Username" required value={username} onChange={e => setUsername(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />}
          <input type="email" placeholder="Email" required value={email} onChange={e => setEmail(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />
          <input type="password" placeholder="Password" required value={password} onChange={e => setPassword(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />
          <button type="submit" className="w-full bg-emerald-400 text-black font-bold p-3 rounded cursor-pointer">{view.toUpperCase()}</button>
          {needsVerification && (
            <div className="text-center pt-2 border-t border-white/10">
              {resendStatus === "sent" ? (
                <div className="space-y-2">
                  <p className="text-xs text-emerald-400">New verification link sent to your inbox.</p>
                  {resendCountdown > 0 && (
                    <p className="text-xs text-gray-500">Resend again in {resendCountdown}s</p>
                  )}
                </div>
              ) : (
                <button 
                  type="button" 
                  onClick={handleResend} 
                  disabled={resendStatus === "sending" || resendCountdown > 0}
                  className="text-xs text-cyan-400 hover:underline bg-transparent border-none cursor-pointer disabled:text-gray-600 disabled:cursor-not-allowed"
                >
                  {resendStatus === "sending" ? "Sending…" : resendCountdown > 0 ? `Resend in ${resendCountdown}s` : "Resend verification link"}
                </button>
              )}
            </div>
          )}
        </form>
      </div>
    </section>
  );
}

function VerifyEmailPage({ token, setView }) {
  const [status, setStatus] = useState("checking"); // checking | ok | error
  const [message, setMessage] = useState("");
  const [resendEmail, setResendEmail] = useState(null);
  const [resendState, setResendState] = useState(null); // null | sending | sent | error

  // React 18 StrictMode runs effects twice in dev (mount → cleanup → mount)
  // to surface exactly this kind of bug. /verify-email is NOT idempotent --
  // it consumes the one-time token -- so without this guard the effect fires
  // the request twice for a single link click: whichever call reaches the
  // server first verifies the account, and the *other* call finds the token
  // already used/cleared and reports back "expired"/"invalid" to the user,
  // even though the account is now verified. The ref persists across the
  // StrictMode remount, so the second invocation is a no-op.
  const startedRef = useRef(false);

  useEffect(() => {
    if (!token) { setStatus("error"); setMessage("No verification link provided."); return; }
    if (startedRef.current) return;
    startedRef.current = true;

    // This tab only ever has the token from the URL -- no localStorage/session
    // context -- so a network hiccup or a slow/unreachable API previously left
    // it stuck on "Verifying your email…" forever. A hard timeout guarantees
    // it always resolves to something the user can act on. It only affects
    // what the UI *shows*; it deliberately does not abort the underlying
    // request, since letting it finish server-side is harmless and aborting
    // it client-side is what caused the double-call bug in the first place.
    let timedOut = false;
    const timeoutId = setTimeout(() => {
      timedOut = true;
      setStatus("error");
      setMessage("The server is taking too long to respond. Check that the API is running and try again.");
    }, 10000);

    fetch(`${API_BASE_URL}/verify-email?token=${encodeURIComponent(token)}`)
      .then(async res => {
        if (timedOut) return;
        const data = await res.json();
        // detail is a plain string for a flatly-invalid token, or
        // {message, email} when the token matched a real (expired) account.
        const detail = data.detail;
        const info = detail && typeof detail === "object" ? detail : { message: detail, email: data.email };
        setResendEmail(info.email || null);
        setStatus(res.ok ? "ok" : "error");
        setMessage(info.message || data.message || "");
      })
      .catch(() => {
        if (timedOut) return;
        setStatus("error");
        setMessage("Couldn't reach the server. Check your connection and try again.");
      })
      .finally(() => clearTimeout(timeoutId));

    return () => clearTimeout(timeoutId);
  }, [token]);

  const handleResend = async () => {
    if (!resendEmail) return;
    setResendState("sending");
    try {
      await fetch(`${API_BASE_URL}/resend-verification`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: resendEmail }),
      });
      setResendState("sent");
    } catch { setResendState("error"); }
  };

  return (
    <section className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950 p-8 text-center">
        {status === "checking" && <p className="text-sm text-gray-400">Verifying your email…</p>}
        {status === "ok" && (
          <>
            <h2 className="text-lg font-semibold text-emerald-400 mb-2">Email verified!</h2>
            <p className="text-sm text-gray-400 mb-6">{message}</p>
            <button onClick={() => setView("login")} className="w-full bg-emerald-400 text-black font-bold p-3 rounded cursor-pointer">GO TO LOGIN</button>
          </>
        )}
        {status === "error" && (
          <>
            <h2 className="text-lg font-semibold text-red-400 mb-2">Verification failed</h2>
            <p className="text-sm text-gray-400 mb-6">{message}</p>
            <div className="space-y-3">
              {/* Re-signing up would just fail with "Account exists" -- this
                  resends a fresh link to the same account instead. Only
                  offered when the token matched a real account (i.e. not for
                  a flatly bogus/malformed link, where there's no email to send to). */}
              {resendEmail && (
                resendState === "sent" ? (
                  <p className="text-xs text-emerald-400">New link sent to {resendEmail} — check your inbox.</p>
                ) : (
                  <button onClick={handleResend} disabled={resendState === "sending"} className="w-full bg-zinc-800 text-white font-bold p-3 rounded cursor-pointer border border-white/20 disabled:opacity-50">
                    {resendState === "sending" ? "Sending…" : "Send me a new link"}
                  </button>
                )
              )}
              <button onClick={() => setView("login")} className="w-full bg-emerald-400 text-black font-bold p-3 rounded cursor-pointer">GO TO LOGIN</button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

/* ---------------------------------------------------------------- */
/* Multi-Domain Dashboard & Vault UI                                */
/* ---------------------------------------------------------------- */

function DashboardView({ username, onLogout }) {
  const [projects, setProjects] = useState([]);
  const [newProjectName, setNewProjectName] = useState("");
  // Fixed state bug: mapped per-project name to isolate form input states
  const [newDomains, setNewDomains] = useState({});

  const loadProjects = () => {
    fetch(`${API_BASE_URL}/${username}`)
      .then(res => res.json())
      .then(data => setProjects(data.projects || []));
  };

  useEffect(() => { loadProjects(); }, [username]);

  const handleAddProject = async () => {
    if (!newProjectName.trim()) return;
    const res = await fetch(`${API_BASE_URL}/${username}/projects/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newProjectName.trim() })
    });
    if (res.ok) {
      setNewProjectName("");
      loadProjects();
    } else {
      const err = await res.json();
      alert(err.detail || "Failed to create project space");
    }
  };

  const handleRemoveProject = async (projectName) => {
    const confirmation = window.confirm(
      `CRITICAL WARNING:\n\nAre you sure you want to completely delete "${projectName}"?\n` +
      `This action is completely irreversible and will permanently wipe all database definitions, ` +
      `all mapped target domains, and completely shred all artifacts residing within the vault directory.`
    );
    
    if (!confirmation) return;
    
    const res = await fetch(`${API_BASE_URL}/${username}/projects/${projectName}/remove`, {
      method: "DELETE"
    });
    
    if (res.ok) {
      loadProjects();
    } else {
      const err = await res.json();
      alert(err.detail || "Failed to complete data wipe");
    }
  };

  const handleAddDomain = async (projectName) => {
    const targetInput = newDomains[projectName] || "";
    if (!targetInput.trim()) return;
    
    const res = await fetch(`${API_BASE_URL}/${username}/${projectName}/domains/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: targetInput.trim() })
    });
    
    if (res.ok) {
      setNewDomains(prev => ({ ...prev, [projectName]: "" }));
      loadProjects();
    } else {
      const err = await res.json();
      alert(err.detail || "Failed to add domain target");
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 pt-24 pb-16 font-sans text-gray-300">
      {/* Dashboard Control Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 border-b border-white/10 pb-6 gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Workspace: <span className="text-emerald-400">{username}</span></h1>
          <div className="flex gap-2 mt-4">
            <input 
              value={newProjectName} 
              onChange={e => setNewProjectName(e.target.value)} 
              placeholder="New Project Name" 
              className="bg-black border border-white/20 px-3 py-1.5 text-sm rounded text-white focus:outline-none focus:border-emerald-400" 
            />
            <button onClick={handleAddProject} className="bg-emerald-500 hover:bg-emerald-600 text-black font-bold px-4 py-1.5 rounded text-sm cursor-pointer border-none transition">Initialize Project</button>
          </div>
        </div>
        <button onClick={onLogout} className="border border-red-500/50 text-red-400 px-4 py-2 rounded text-sm hover:bg-red-500/10 cursor-pointer bg-transparent transition self-end md:self-auto">Sign Out</button>
      </div>

      {/* Projects Iteration Grid */}
      {projects.map(proj => (
        <div key={proj.name} className="mb-12 border border-white/10 p-6 rounded-xl bg-zinc-900/40">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 border-b border-white/5 pb-4 gap-4">
            <div className="flex items-center gap-4">
              <h2 className="text-xl font-bold text-white">{proj.name}</h2>
              <button 
                onClick={() => handleRemoveProject(proj.name)} 
                className="text-[11px] border border-red-500/30 text-red-400/70 hover:text-red-400 hover:bg-red-500/10 px-2 py-1 rounded cursor-pointer bg-transparent transition"
              >
                Wipe Project Space
              </button>
            </div>
            <div className="flex gap-2 w-full sm:w-auto">
              <input 
                value={newDomains[proj.name] || ""} 
                onChange={e => setNewDomains(prev => ({ ...prev, [proj.name]: e.target.value }))} 
                placeholder="new-target.com" 
                className="bg-black border border-white/20 px-3 py-1.5 text-sm rounded text-white flex-grow sm:flex-none focus:outline-none focus:border-blue-500" 
              />
              <button onClick={() => handleAddDomain(proj.name)} className="bg-blue-600/80 hover:bg-blue-600 text-white px-4 py-1.5 rounded text-sm cursor-pointer border-none transition shrink-0">+ Add Target</button>
            </div>
          </div>
          
          <div className="grid gap-6">
            {proj.domains.map(dom => (
              <DomainCard key={dom.name} domain={dom.name} project={proj.name} username={username} refreshProjects={loadProjects} />
            ))}
            {proj.domains.length === 0 && <p className="text-gray-500 text-sm text-center py-4 italic">No evaluation domains added to this project context yet.</p>}
          </div>
        </div>
      ))}
      
      {projects.length === 0 && (
        <div className="text-center py-16 border border-dashed border-white/10 rounded-2xl">
          <p className="text-gray-500 font-mono">No active project containers. Initialize a new project above to begin scanning.</p>
        </div>
      )}
    </div>
  );
}

function DomainCard({ domain, project, username, refreshProjects }) {
  const [files, setFiles] = useState([]);
  const [viewFile, setViewFile] = useState(null);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportData, setReportData] = useState(null); // { report, files_analyzed }
  const [reportError, setReportError] = useState(null);
  const [openApiSpec, setOpenApiSpec] = useState(null); // { name, size } | null
  const fileInputRef = useRef();
  const openApiInputRef = useRef();
  const pollRef = useRef(null);

  const loadVault = () => {
    return fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault`)
      .then(res => res.json())
      .then(data => {
        const fetchedFiles = data.files || [];
        setFiles(fetchedFiles);
        return fetchedFiles;
      });
  };

  const loadOpenApiSpec = () => {
    return fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/openapi`)
      .then(res => res.json())
      .then(data => setOpenApiSpec(data.file || null));
  };

  const checkStatus = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/pipeline/status`);
      if (!res.ok) return false;
      const data = await res.json();
      return !!data.running;
    } catch {
      return false;
    }
  };

  useEffect(() => {
    let cancelled = false;
    loadVault();
    loadOpenApiSpec();
    // On mount (including after a page refresh) ask the backend for ground truth —
    // if a pipeline is already running for this domain, resume showing it as running
    // and start polling, instead of defaulting to "idle" just because local state reset.
    (async () => {
      const running = await checkStatus();
      if (!cancelled && running) startPolling();
    })();
    return () => { cancelled = true; };
  }, []);

  // Clean up any in-flight polling if the card unmounts (e.g. domain removed)
  useEffect(() => () => stopPolling(), []);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setPipelineRunning(false);
  };

  const startPolling = () => {
    if (pollRef.current) return; // already polling
    setPipelineRunning(true);

    pollRef.current = setInterval(async () => {
      const running = await checkStatus();
      if (!running) {
        stopPolling();
        loadVault(); // pull the fresh results now that the run has finished
      }
    }, 3000);
  };

  const handleRun = async () => {
    if (pipelineRunning) return; // guard against a rapid double-click race
    setPipelineRunning(true); // lock the button immediately, before the request even resolves
    try {
      const res = await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/pipeline/start`, { method: "POST" });
      if (!res.ok && res.status !== 409) {
        // 409 just means "already running" — that's fine, we resync to it below.
        // Anything else (404 workspace missing, etc.) is a real failure.
        const err = await res.json().catch(() => ({}));
        alert(err.detail || "Failed to start pipeline");
      }
    } catch {
      alert("Failed to reach the orchestrator API.");
    }
    // Whatever happened, ask the backend what's actually true rather than assuming.
    const running = await checkStatus();
    if (running) startPolling();
    else setPipelineRunning(false);
  };

  const handleDeleteDomain = async () => {
    await fetch(`${API_BASE_URL}/${username}/${project}/domains/${domain}/remove`, { method: "DELETE" });
    refreshProjects();
  };

  const handleUpload = async (e) => {
    if (!e.target.files[0]) return;
    const formData = new FormData();
    formData.append("file", e.target.files[0]);
    await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/upload`, { method: "POST", body: formData });
    loadVault();
  };

  const handleOpenApiUpload = async (e) => {
    if (!e.target.files[0]) return;
    const formData = new FormData();
    formData.append("file", e.target.files[0]);
    // Backend wipes any previous spec first, so this always fully replaces it.
    await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/openapi/upload`, { method: "POST", body: formData });
    e.target.value = ""; // allow re-selecting the same filename again later
    loadOpenApiSpec();
  };

  const handleViewOpenApiSpec = async () => {
    const res = await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/openapi/view`);
    if (res.ok) {
      const data = await res.json();
      setViewFile({ name: data.name, content: data.content });
    } else alert("Cannot read this file type as text.");
  };

  const handleDeleteOpenApiSpec = async () => {
    // Deletes just the spec — the domain and its other vault artifacts are untouched.
    await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/openapi`, { method: "DELETE" });
    loadOpenApiSpec();
  };

  const handleView = async (filepath) => {
    const res = await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/view/${filepath}`);
    if (res.ok) {
      const data = await res.json();
      setViewFile({ name: filepath, content: data.content });
    } else alert("Cannot read this file type as text.");
  };

  const handleDeleteFile = async (filepath) => {
    await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/vault/delete/${filepath}`, { method: "DELETE" });
    loadVault();
  };

  const handleViewReport = async () => {
    setReportError(null);
    setReportData(null);
    setReportLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/${username}/${project}/${domain}/report`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to generate report");
      setReportData(data);
    } catch (err) {
      setReportError(err.message);
    } finally {
      setReportLoading(false);
    }
  };

  return (
    <div className="border border-white/5 bg-black/60 p-5 rounded-lg">
      <div className="flex justify-between items-center mb-4 border-b border-white/5 pb-3">
        <h3 className="font-mono text-cyan-400 text-lg">{domain}</h3>
        <div className="flex gap-3">
          <button onClick={handleRun} disabled={pipelineRunning} className={`px-3 py-1 rounded text-xs font-bold transition border ${pipelineRunning ? "bg-yellow-500/10 border-yellow-500/50 text-yellow-400 cursor-wait" : "bg-emerald-500/10 border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/20 cursor-pointer"}`}>
            {pipelineRunning ? "Running…" : "Run Pipeline"}
          </button>
          <button onClick={handleViewReport} disabled={pipelineRunning || reportLoading || files.length === 0} title={files.length === 0 ? "No vault artifacts yet — run the pipeline first" : ""} className={`px-3 py-1 rounded text-xs font-bold transition border ${(pipelineRunning || files.length === 0) ? "bg-white/5 border-white/10 text-gray-600 cursor-not-allowed" : reportLoading ? "bg-purple-500/10 border-purple-500/50 text-purple-300 cursor-wait" : "bg-purple-500/10 border-purple-500/50 text-purple-300 hover:bg-purple-500/20 cursor-pointer"}`}>
            {reportLoading ? "Analyzing…" : "View Report"}
          </button>
          <button onClick={handleDeleteDomain} className="text-red-500 hover:text-red-400 text-xs px-2 cursor-pointer bg-transparent border-none">Remove Domain</button>
        </div>
      </div>
      
      <div className="text-sm">
        {/* OpenAPI / Swagger spec — stored in its own directory, separate from scan
            artifacts. Survives pipeline re-runs and is only removed when the domain
            itself is deleted, unless the user deletes it explicitly below. */}
        <div className="mb-4 pb-4 border-b border-white/5">
          <div className="flex justify-between items-center mb-2">
            <p className="uppercase tracking-wider text-xs text-gray-500 font-bold">OpenAPI / Swagger Spec</p>
            <div>
              <input type="file" ref={openApiInputRef} onChange={handleOpenApiUpload} className="hidden" />
              <button onClick={() => openApiInputRef.current.click()} className="text-xs text-blue-400 border border-blue-400/30 px-2 py-1 rounded hover:bg-blue-400/10 cursor-pointer bg-transparent">
                {openApiSpec ? "↻ Replace Spec" : "+ Upload Spec"}
              </button>
            </div>
          </div>

          {openApiSpec ? (
            <div className="flex justify-between items-center bg-zinc-900/50 px-3 py-2 rounded border border-white/5">
              <span className="font-mono text-xs text-gray-300">
                {openApiSpec.name} <span className="text-gray-600">({openApiSpec.size})</span>
              </span>
              <div className="flex gap-3 text-xs">
                <button onClick={handleViewOpenApiSpec} className="text-cyan-400 hover:underline cursor-pointer bg-transparent border-none p-0">View</button>
                <button onClick={handleDeleteOpenApiSpec} className="text-red-400 hover:underline cursor-pointer bg-transparent border-none p-0">Delete</button>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-600 italic">No spec uploaded. It's stored separately and won't be cleared by pipeline re-runs.</p>
          )}
        </div>

        <div className="flex justify-between items-center mb-3">
          <div className="flex items-center gap-2">
            <p className="uppercase tracking-wider text-xs text-gray-500 font-bold">Vault Artifacts</p>
            {pipelineRunning && (
              <span className="flex items-center gap-1.5 text-[10px] text-yellow-400">
                <span className="h-1.5 w-1.5 rounded-full bg-yellow-400 animate-pulse" />
                scanning…
              </span>
            )}
          </div>
          <div>
            <input type="file" ref={fileInputRef} onChange={handleUpload} className="hidden" />
            <button onClick={() => fileInputRef.current.click()} className="text-xs text-blue-400 border border-blue-400/30 px-2 py-1 rounded hover:bg-blue-400/10 cursor-pointer bg-transparent">+ Upload File</button>
          </div>
        </div>

        {files.length === 0 ? (
          <p className="text-xs text-gray-600 italic">No files in vault.</p>
        ) : (
          <div className="grid gap-2">
            {files.map(f => (
              <div key={f.name} className="flex justify-between items-center bg-zinc-900/50 px-3 py-2 rounded border border-white/5">
                <span className="font-mono text-xs text-gray-300">{f.name}</span>
                <div className="flex gap-3 text-xs">
                  <button onClick={() => handleView(f.name)} className="text-cyan-400 hover:underline cursor-pointer bg-transparent border-none p-0">View</button>
                  <button onClick={() => handleDeleteFile(f.name)} className="text-red-400 hover:underline cursor-pointer bg-transparent border-none p-0">Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* AI Report Modal */}
      {(reportLoading || reportData || reportError) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-6">
          <div className="bg-zinc-950 border border-white/10 rounded-xl w-full max-w-3xl max-h-[85vh] flex flex-col">
            <div className="flex justify-between items-center p-4 border-b border-white/10">
              <h4 className="font-mono text-purple-300 text-sm">AI Report — {domain}</h4>
              <button onClick={() => { setReportData(null); setReportError(null); }} className="text-gray-400 hover:text-white font-bold cursor-pointer bg-transparent border-none">✕</button>
            </div>
            <div className="p-5 overflow-auto">
              {reportLoading && (
                <div className="flex items-center gap-2 text-sm text-purple-300">
                  <span className="h-2 w-2 rounded-full bg-purple-400 animate-pulse" />
                  Sending vault artifacts to the AI analyst…
                </div>
              )}
              {reportError && <p className="text-red-400 text-sm">{reportError}</p>}
              {reportData && (
                <>
                  <p className="text-[11px] uppercase tracking-wider text-gray-500 mb-3">
                    Analyzed {reportData.files_analyzed.length} artifact{reportData.files_analyzed.length === 1 ? "" : "s"}: {reportData.files_analyzed.join(", ")}
                  </p>
                  <div className="text-sm text-gray-200 leading-relaxed">
                    <ReactMarkdown
                      remarkPlugins={[remarkGfm]}
                      components={{
                        h1: ({ node, ...p }) => <h1 className="text-lg font-bold text-white mt-4 mb-2 first:mt-0" {...p} />,
                        h2: ({ node, ...p }) => <h2 className="text-base font-bold text-purple-300 mt-4 mb-2 first:mt-0" {...p} />,
                        h3: ({ node, ...p }) => <h3 className="text-sm font-bold text-purple-200 mt-3 mb-1.5" {...p} />,
                        p: ({ node, ...p2 }) => <p className="mb-3" {...p2} />,
                        ul: ({ node, ...p }) => <ul className="list-disc list-outside pl-5 mb-3 space-y-1" {...p} />,
                        ol: ({ node, ...p }) => <ol className="list-decimal list-outside pl-5 mb-3 space-y-1" {...p} />,
                        li: ({ node, ...p }) => <li className="text-gray-200" {...p} />,
                        strong: ({ node, ...p }) => <strong className="font-bold text-white" {...p} />,
                        em: ({ node, ...p }) => <em className="italic text-gray-300" {...p} />,
                        a: ({ node, ...p }) => <a className="text-purple-400 underline hover:text-purple-300" target="_blank" rel="noreferrer" {...p} />,
                        code: ({ node, ...p }) => <code className="bg-white/10 text-purple-200 rounded px-1 py-0.5 font-mono text-xs" {...p} />,
                        pre: ({ node, ...p }) => <pre className="bg-black/60 border border-white/10 rounded-lg p-3 font-mono text-xs overflow-x-auto my-2 [&>code]:bg-transparent [&>code]:text-gray-200 [&>code]:p-0 [&>code]:rounded-none" {...p} />,
                        blockquote: ({ node, ...p }) => <blockquote className="border-l-2 border-purple-500/50 pl-3 italic text-gray-400 my-2" {...p} />,
                        hr: () => <hr className="border-white/10 my-4" />,
                        table: ({ node, ...p }) => <div className="overflow-x-auto my-3"><table className="min-w-full text-xs border border-white/10" {...p} /></div>,
                        th: ({ node, ...p }) => <th className="border border-white/10 bg-white/5 px-2 py-1 text-left font-semibold text-gray-300" {...p} />,
                        td: ({ node, ...p }) => <td className="border border-white/10 px-2 py-1" {...p} />,
                      }}
                    >
                      {reportData.report}
                    </ReactMarkdown>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* File Viewer Modal */}
      {viewFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-6">
          <div className="bg-zinc-950 border border-white/10 rounded-xl w-full max-w-4xl max-h-[80vh] flex flex-col">
            <div className="flex justify-between items-center p-4 border-b border-white/10">
              <h4 className="font-mono text-emerald-400 text-sm">{viewFile.name}</h4>
              <button onClick={() => setViewFile(null)} className="text-gray-400 hover:text-white font-bold cursor-pointer bg-transparent border-none">✕</button>
            </div>
            <div className="p-4 overflow-auto">
              <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">{viewFile.content}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  // A verification email link lands here as /?token=... -- if one's present, 
  // that takes priority over whatever else localStorage says about the session.
  const verifyToken = new URLSearchParams(window.location.search).get("token");

  const [activeUser, setActiveUser] = useState(() => localStorage.getItem("itek_user") || null);
  const [view, setView] = useState(() => verifyToken ? "verify" : localStorage.getItem("itek_user") ? "dashboard" : "landing");

  const navigateTo = (targetView) => setView(targetView);
  const handleLoginSuccess = (user) => { localStorage.setItem("itek_user", user); setActiveUser(user); navigateTo("dashboard"); };
  const handleLogout = () => { localStorage.removeItem("itek_user"); setActiveUser(null); navigateTo("landing"); };

  const showDashboard = activeUser && view !== "verify";

  return (
    <div className="min-h-screen bg-black font-sans text-gray-100 antialiased">
      <Navbar setView={navigateTo} view={showDashboard ? "dashboard" : view} />
      {view === "verify" ? (
        <VerifyEmailPage token={verifyToken} setView={navigateTo} />
      ) : showDashboard ? (
        <DashboardView username={activeUser} onLogout={handleLogout} />
      ) : view === "landing" ? (
        <><Hero setView={navigateTo} /><Capabilities /><TerminalDemo /></>
      ) : (
        <AuthPage view={view} setView={navigateTo} onLoginSuccess={handleLoginSuccess} />
      )}
    </div>
  );
}