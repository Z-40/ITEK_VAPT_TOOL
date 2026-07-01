import { useState, useEffect, useRef } from "react";

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

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const endpoint = view === "login" ? "/login" : "/signup";
      const payload = view === "login" ? { email, password } : { email, username, password };
      const res = await fetch(`http://127.0.0.1:8000${endpoint}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail);
      if (view === "login") onLoginSuccess(data.username); else setView("login");
    } catch (err) { setError(err.message); }
  };

  return (
    <section className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950 p-8">
        <form onSubmit={handleSubmit} className="space-y-5">
          {error && <p className="text-red-400 text-xs text-center">{error}</p>}
          {view === "signup" && <input placeholder="Username" required value={username} onChange={e => setUsername(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />}
          <input type="email" placeholder="Email" required value={email} onChange={e => setEmail(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />
          <input type="password" placeholder="Password" required value={password} onChange={e => setPassword(e.target.value)} className="w-full p-3 bg-black border border-white/20 text-white rounded" />
          <button type="submit" className="w-full bg-emerald-400 text-black font-bold p-3 rounded">{view.toUpperCase()}</button>
        </form>
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
    fetch(`http://127.0.0.1:8000/${username}`)
      .then(res => res.json())
      .then(data => setProjects(data.projects || []));
  };

  useEffect(() => { loadProjects(); }, [username]);

  const handleAddProject = async () => {
    if (!newProjectName.trim()) return;
    const res = await fetch(`http://127.0.0.1:8000/${username}/projects/add`, {
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
    
    const res = await fetch(`http://127.0.0.1:8000/${username}/projects/${projectName}/remove`, {
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
    
    const res = await fetch(`http://127.0.0.1:8000/${username}/${projectName}/domains/add`, {
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
  const fileInputRef = useRef();
  const pollRef = useRef(null);

  const loadVault = () => {
    return fetch(`http://127.0.0.1:8000/${username}/${project}/${domain}/vault`)
      .then(res => res.json())
      .then(data => {
        const fetchedFiles = data.files || [];
        setFiles(fetchedFiles);
        return fetchedFiles;
      });
  };

  useEffect(() => { loadVault(); }, []);

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
    const startedAt = Date.now();
    const MAX_POLL_MS = 5 * 60 * 1000; // safety timeout: stop after 5 minutes regardless

    pollRef.current = setInterval(async () => {
      const fetchedFiles = await loadVault();

      const finished = fetchedFiles.some(f => f.name === "findings_report.json");
      const timedOut = Date.now() - startedAt > MAX_POLL_MS;

      if (finished || timedOut) {
        stopPolling();
      }
    }, 3000);
  };

  const handleRun = async () => {
    await fetch(`http://127.0.0.1:8000/${username}/${project}/${domain}/pipeline/start`, { method: "POST" });
    startPolling();
  };

  const handleDeleteDomain = async () => {
    await fetch(`http://127.0.0.1:8000/${username}/${project}/domains/${domain}/remove`, { method: "DELETE" });
    refreshProjects();
  };

  const handleUpload = async (e) => {
    if (!e.target.files[0]) return;
    const formData = new FormData();
    formData.append("file", e.target.files[0]);
    await fetch(`http://127.0.0.1:8000/${username}/${project}/${domain}/vault/upload`, { method: "POST", body: formData });
    loadVault();
  };

  const handleView = async (filepath) => {
    const res = await fetch(`http://127.0.0.1:8000/${username}/${project}/${domain}/vault/view/${filepath}`);
    if (res.ok) {
      const data = await res.json();
      setViewFile({ name: filepath, content: data.content });
    } else alert("Cannot read this file type as text.");
  };

  const handleDeleteFile = async (filepath) => {
    await fetch(`http://127.0.0.1:8000/${username}/${project}/${domain}/vault/delete/${filepath}`, { method: "DELETE" });
    loadVault();
  };

  return (
    <div className="border border-white/5 bg-black/60 p-5 rounded-lg">
      <div className="flex justify-between items-center mb-4 border-b border-white/5 pb-3">
        <h3 className="font-mono text-cyan-400 text-lg">{domain}</h3>
        <div className="flex gap-3">
          <button onClick={handleRun} disabled={pipelineRunning} className={`px-3 py-1 rounded text-xs font-bold transition border ${pipelineRunning ? "bg-yellow-500/10 border-yellow-500/50 text-yellow-400 cursor-wait" : "bg-emerald-500/10 border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/20 cursor-pointer"}`}>
            {pipelineRunning ? "Running…" : "Run Pipeline"}
          </button>
          <button onClick={handleDeleteDomain} className="text-red-500 hover:text-red-400 text-xs px-2 cursor-pointer bg-transparent border-none">Remove Domain</button>
        </div>
      </div>
      
      <div className="text-sm">
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
            <button onClick={() => fileInputRef.current.click()} className="text-xs text-blue-400 border border-blue-400/30 px-2 py-1 rounded hover:bg-blue-400/10 cursor-pointer bg-transparent">+ Upload Spec (openapi_spec.json)</button>
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
  const [activeUser, setActiveUser] = useState(() => localStorage.getItem("itek_user") || null);
  const [view, setView] = useState(() => localStorage.getItem("itek_user") ? "dashboard" : "landing");

  const navigateTo = (targetView) => setView(targetView);
  const handleLoginSuccess = (user) => { localStorage.setItem("itek_user", user); setActiveUser(user); navigateTo("dashboard"); };
  const handleLogout = () => { localStorage.removeItem("itek_user"); setActiveUser(null); navigateTo("landing"); };

  return (
    <div className="min-h-screen bg-black font-sans text-gray-100 antialiased">
      <Navbar setView={navigateTo} view={activeUser ? "dashboard" : view} />
      {activeUser ? <DashboardView username={activeUser} onLogout={handleLogout} /> : view === "landing" ? <><Hero setView={navigateTo} /><Capabilities /><TerminalDemo /></> : <AuthPage view={view} setView={navigateTo} onLoginSuccess={handleLoginSuccess} />}
    </div>
  );
}