import { useState, useEffect, useRef } from "react";

/* ---------------------------------------------------------------- */
/* Icons (inline SVG)                                               */
/* ---------------------------------------------------------------- */

function IconRadar({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      <circle cx="12" cy="12" r="9" strokeOpacity="0.9" />
      <circle cx="12" cy="12" r="5" strokeOpacity="0.5" />
      <path d="M12 12V4" strokeLinecap="round" />
      <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconBracket({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M9 18 5 12 9 6" />
      <path d="M15 6l4 6-4 6" />
    </svg>
  );
}

function IconShieldCheck({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 3l7 3v6c0 5-3.2 7.8-7 9-3.8-1.2-7-4-7-9V6z" />
      <path d="M9 12.2l2 2 4-4.4" />
    </svg>
  );
}

function IconBug({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M9 7V5a3 3 0 0 1 6 0v2" />
      <rect x="6" y="7" width="12" height="11" rx="5.5" />
      <path d="M6 12H3M21 12h-3M8 4 6 2M16 4l2-2M9 18l-2 2M15 18l2 2" />
    </svg>
  );
}

function IconTarget({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="12" cy="12" r="0.8" fill="currentColor" stroke="none" />
      <path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3" strokeLinecap="round" />
    </svg>
  );
}

function IconLockBox({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

function IconUploadCloud({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12" />
    </svg>
  );
}

function IconDocFile({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

function IconTrashCan({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
      <line x1="10" y1="11" x2="10" y2="17" />
      <line x1="14" y1="11" x2="14" y2="17" />
    </svg>
  );
}

/* ---------------------------------------------------------------- */
/* Context Configuration Constants                                  */
/* ---------------------------------------------------------------- */

const NAV_LINKS = [
  { href: "#capabilities", label: "Capabilities" },
  { href: "#demo", label: "Live demo" },
  { href: "#", label: "Docs" },
];

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
  { type: "log", text: "[00:09] fingerprinting services ...... nginx 1.18, Apache 2.4.49, OpenSSH 8.2" },
  { type: "log", text: "[00:14] cross-referencing CVE database" },
  { type: "critical", text: "CVE-2021-41773 — Apache 2.4.49 path traversal, RCE confirmed" },
  { type: "high", text: 'CVE-2020-1938 — AJP "Ghostcat" file read confirmed' },
  { type: "log", text: "[00:22] testing 312 injection points" },
  { type: "critical", text: "login.acme-corp.io/api/auth — SQLi (time-based) confirmed" },
  { type: "medium", text: "shop.acme-corp.io/search — reflected XSS" },
  { type: "log", text: "[00:31] generating proof-of-concept evidence" },
  { type: "done", text: "4 confirmed findings — report ready" },
];

/* ---------------------------------------------------------------- */
/* Base Presentation Layers                                         */
/* ---------------------------------------------------------------- */

function Navbar({ setView, view }) {
  const [open, setOpen] = useState(false);
  const handleNavClick = (viewName) => { 
    setView(viewName); 
    setOpen(false); 
  };

  return (
    <nav className="fixed inset-x-0 top-0 z-50 border-b border-white/10 bg-black/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        {/* Brand Identity / Workspace Router */}
        <button onClick={() => handleNavClick(localStorage.getItem("itek_user") ? "dashboard" : "landing")} className="flex items-center gap-2.5 bg-transparent border-none outline-none cursor-pointer">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-400 font-mono text-sm font-bold text-black">I</span>
          <span className="font-mono text-lg font-bold tracking-tight text-white">ITEK</span>
        </button>

        {/* Navigation Core Links */}
        <div className="items-center gap-8 text-sm text-gray-400 flex">
          {view === "landing" ? (
            <div className="hidden gap-8 md:flex">
              {NAV_LINKS.map((link) => <a key={link.label} href={link.href} className="transition-colors hover:text-white">{link.label}</a>)}
            </div>
          ) : view !== "dashboard" ? (
            <button onClick={() => handleNavClick("landing")} className="transition-colors hover:text-white text-sm text-gray-400 bg-transparent border-none outline-none cursor-pointer">← Back to Home</button>
          ) : (
            <span className="text-emerald-400 font-mono text-xs">Secured Management Portal</span>
          )}
        </div>

        {/* Desktop Interface Action Triggers (Visible on big screens) */}
        {view !== "dashboard" && (
          <div className="hidden items-center gap-3 md:flex">
            <button onClick={() => handleNavClick("login")} className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none bg-transparent border-none cursor-pointer ${view === 'login' ? 'text-emerald-400' : 'text-gray-300 hover:text-white'}`}>Log in</button>
            <button onClick={() => handleNavClick("signup")} className="rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-sm font-semibold text-black transition hover:brightness-110 focus:outline-none border-none cursor-pointer">Sign up</button>
          </div>
        )}

        {/* Mobile Hamburger Menu Toggle Trigger (Visible on small viewports) */}
        {view !== "dashboard" && (
          <button
            onClick={() => setOpen(!open)}
            className="text-gray-400 md:hidden bg-transparent border-none cursor-pointer hover:text-white focus:outline-none flex items-center"
            aria-label="Toggle structural menu layout"
          >
            {open ? (
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            ) : (
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75"><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 17h16" /></svg>
            )}
          </button>
        )}
      </div>

      {/* Mobile Drawer Panel (Conditionally slides open below header line) */}
      {open && view !== "dashboard" && (
        <div className="border-t border-white/10 bg-zinc-950/95 px-6 py-5 md:hidden font-mono text-sm">
          <div className="flex flex-col gap-4">
            {view === "landing" && NAV_LINKS.map((link) => (
              <a key={link.label} href={link.href} onClick={() => setOpen(false)} className="text-gray-400 hover:text-white transition-colors py-1">
                {link.label}
              </a>
            ))}
            <div className="flex flex-col gap-3 border-t border-white/5 pt-4 mt-1">
              <button onClick={() => handleNavClick("login")} className="w-full rounded-xl border border-white/10 bg-transparent py-2.5 font-medium text-gray-300 hover:text-white cursor-pointer">
                Log in
              </button>
              <button onClick={() => handleNavClick("signup")} className="w-full rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-2.5 font-bold text-black cursor-pointer">
                Sign up
              </button>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}

function Hero({ setView }) {
  return (
    <section id="top" className="relative overflow-hidden px-6 pb-24 pt-40">
      <div className="pointer-events-none absolute inset-0 opacity-60" style={{ backgroundImage: "linear-gradient(to right, rgba(255,255,255,0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.05) 1px, transparent 1px)", backgroundSize: "48px 48px" }} />
      <div className="relative z-10 mx-auto max-w-4xl text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/5 px-4 py-1.5 font-mono text-xs uppercase tracking-[0.2em] text-emerald-400">Offensive Security Platform</span>
        <h1 className="mt-8 font-mono text-5xl font-bold leading-[1.05] tracking-tight text-white sm:text-6xl lg:text-7xl">Attack your own<br /><span className="bg-gradient-to-r from-emerald-300 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">infrastructure first.</span></h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-gray-400 sm:text-xl">ITEK automates recon, exploitation, and CVE correlation across your entire attack surface.</p>
        <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row"><button onClick={() => setView("signup")} className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-8 py-3.5 text-sm font-semibold text-black transition hover:brightness-110">Start an assessment</button></div>
      </div>
    </section>
  );
}

function Capabilities() { return <section id="capabilities" className="mx-auto max-w-7xl px-6 py-24"><div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">{FEATURES.map((f) => (<div key={f.n} className="group relative rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition-all duration-300 hover:border-emerald-400/40"><div className="mb-5 flex items-center justify-between"><div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400"><f.icon className="h-5 w-5" /></div></div><p className="mb-2 truncate font-mono text-[11px] text-cyan-400/80">$ {f.cmd}</p><h3 className="mb-2 text-lg font-semibold text-white">{f.title}</h3><p className="text-sm leading-relaxed text-gray-400">{f.desc}</p></div>))}</div></section>; }

function TerminalDemo() { 
  const [visibleCount, setVisibleCount] = useState(0); 
  useEffect(() => { const id = setInterval(() => { setVisibleCount((c) => (c >= SCAN_LINES.length + 4 ? 0 : c + 1)); }, 450); return () => clearInterval(id); }, []); 
  const shown = SCAN_LINES.slice(0, Math.min(visibleCount, SCAN_LINES.length)); 
  return <section id="demo" className="px-6 py-24"><div className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-white/10 bg-zinc-950/80 p-6 font-mono text-[13px] sm:text-sm">{shown.map((line, i) => { if (line.type === "cmd") return <p key={i} className="text-gray-200"><span className="text-emerald-400">itek@core</span>:~# {line.text}</p>; return <p key={i} className="text-gray-500">{line.text}</p>; })}<span className="inline-block h-4 w-2 bg-emerald-400/80 align-middle animate-pulse" /></div></section>; 
}

/* ---------------------------------------------------------------- */
/* Auth Component Pipeline                                          */
/* ---------------------------------------------------------------- */

function AuthPage({ view, setView, onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const targetEndpoint = view === "login" ? "/login" : "/signup";
    const payload = view === "login" ? { email, password } : { email, username, password };

    try {
      const response = await fetch(`http://127.0.0.1:8000${targetEndpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Authentication entry blocked.");
      
      if (view === "login") onLoginSuccess(data.username);
      else { alert("Registration verified. Proceeding to access gateway."); setView("login"); }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="relative flex min-h-[calc(100vh-4rem)] items-center justify-center px-6 pt-24 pb-12">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950/70 p-8 shadow-2xl backdrop-blur-xl">
        <form onSubmit={handleSubmit} className="space-y-5">
          {error && <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-center font-mono text-xs text-red-400">{error}</div>}
          {view === "signup" && (
            <div>
              <label className="block font-mono text-xs text-gray-400 uppercase mb-2">Username</label>
              <input type="text" required value={username} onChange={(e) => setUsername(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white outline-none" />
            </div>
          )}
          <div>
            <label className="block font-mono text-xs text-gray-400 uppercase mb-2">Email</label>
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white outline-none" />
          </div>
          <div>
            <label className="block font-mono text-xs text-gray-400 uppercase mb-2">Password</label>
            <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white outline-none" />
          </div>
          <button type="submit" disabled={loading} className="w-full rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-3.5 font-mono text-sm font-bold text-black">{loading ? "Synchronizing..." : view.toUpperCase()}</button>
        </form>
      </div>
    </section>
  );
}

/* ---------------------------------------------------------------- */
/* Dashboard & Encrypted Vault UI Block                             */
/* ---------------------------------------------------------------- */

function DashboardView({ username, onLogout }) {
  const [activeTab, setActiveTab] = useState("projects");
  const [profileData, setProfileData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [projectFilter, setProjectFilter] = useState("");
  const [selectedProject, setSelectedProject] = useState(null);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetch(`http://127.0.0.1:8000/${username}`)
      .then((res) => res.json())
      .then((data) => { setProfileData(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [username]);

  const handleProjectClick = async (projectName) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/${username}/${projectName}`);
      const data = await res.json();
      setSelectedProject(data);
      setActiveTab("project-detail");
    } catch (err) {
      alert("Error isolating target configuration profile mappings.");
    }
  };

  const handleVaultUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`http://127.0.0.1:8000/${username}/${selectedProject.project_info.name}/vault/upload`, {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload constraint failure");

      setSelectedProject((prev) => ({
        ...prev,
        vault: [...prev.vault, data.asset],
      }));
    } catch (err) {
      alert(err.message);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleFileDownload = (fileId) => {
    // Routes the browser window frame link to fire the clean attachment transmission node
    window.location.href = `http://127.0.0.1:8000/${username}/${selectedProject.project_info.name}/vault/download/${fileId}`;
  };

  const handleVaultDelete = async (fileId) => {
    if (!confirm("Are you certain you want to permanently purge this file asset from vault inventory?")) return;
    try {
      const res = await fetch(`http://127.0.0.1:8000/${username}/${selectedProject.project_info.name}/vault/${fileId}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Purge authorization fault.");

      setSelectedProject((prev) => ({
        ...prev,
        vault: prev.vault.filter((item) => item.id !== fileId),
      }));
    } catch (err) {
      alert(err.message);
    }
  };

  if (loading) return <div className="pt-32 text-center font-mono text-gray-500">Decrypting target environments...</div>;
  if (!profileData) return <div className="pt-32 text-center font-mono text-red-400">Security Clearance Violation.</div>;

  const filteredProjects = profileData.projects.filter(p => p.name.toLowerCase().includes(projectFilter.toLowerCase()));

  return (
    <div className="mx-auto max-w-7xl px-6 pt-24 pb-16 font-mono text-sm text-gray-300">
      <div className="flex flex-col items-start gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{profileData.username}</h1>
          <p className="text-gray-500 mt-1">{profileData.role} @ <span className="text-emerald-400">{profileData.company}</span></p>
        </div>
        <button onClick={onLogout} className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs font-bold text-red-400 hover:bg-red-500/20 transition cursor-pointer">Sign Out</button>
      </div>

      <div className="flex gap-6 border-b border-white/10 my-6 text-xs uppercase tracking-wider">
        {["overview", "projects", "account", "settings"].map((tab) => (
          <button key={tab} onClick={() => { setActiveTab(tab); setSelectedProject(null); }} className={`pb-3 font-bold bg-transparent border-none cursor-pointer ${activeTab === tab ? "border-b-2 border-emerald-400 text-white" : "text-gray-500 hover:text-gray-300"}`}>
            {tab} {tab === "projects" && `(${profileData.projects.length})`}
          </button>
        ))}
      </div>

      {activeTab === "overview" && <div className="space-y-4 border border-white/10 bg-zinc-950/40 rounded-xl p-6"><p className="text-gray-400 text-xs leading-relaxed">{profileData.bio}</p></div>}

      {activeTab === "projects" && (
        <div className="space-y-4">
          <input type="text" placeholder="Search operational targets..." value={projectFilter} onChange={(e) => setProjectFilter(e.target.value)} className="w-full max-w-md rounded-xl border border-white/10 bg-white/[0.02] px-4 py-2 text-xs text-white outline-none focus:border-emerald-400/40" />
          <div className="divide-y divide-white/10 border-t border-b border-white/10">
            {filteredProjects.map((project) => (
              <div key={project.name} className="flex items-center justify-between py-4 hover:bg-white/[0.01] px-2 transition rounded-lg">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <button onClick={() => handleProjectClick(project.name)} className="text-base font-bold text-emerald-400 hover:underline bg-transparent border-none p-0 cursor-pointer">{project.name}</button>
                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] text-gray-500">{project.visibility}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "project-detail" && selectedProject && (
        <div className="space-y-6">
          <button onClick={() => setActiveTab("projects")} className="text-xs text-gray-500 hover:text-white cursor-pointer bg-transparent border-none">← Back to operational matrix</button>
          
          <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6 space-y-4">
            <h3 className="text-white text-lg font-bold">{selectedProject.project_info.name}</h3>
            <pre className="bg-black/50 p-3 rounded border border-white/5 text-xs text-cyan-400">{JSON.stringify(selectedProject.scope_rules, null, 2)}</pre>
          </div>

          {/* Secure Isolated Vault Partition Layout */}
          <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/5 pb-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
                  <IconLockBox className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="text-white font-bold text-sm">Isolated Project Vault</h4>
                  <p className="text-gray-500 text-[11px]">Secure storage space for scope configurations, logs, and evidence.</p>
                </div>
              </div>
              
              <div>
                <input type="file" ref={fileInputRef} onChange={handleVaultUpload} className="hidden" id="vault-uploader-node" />
                <label htmlFor="vault-uploader-node" className={`inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-xs font-bold text-black hover:brightness-110 cursor-pointer transition ${uploading ? "opacity-50 pointer-events-none" : ""}`}>
                  <IconUploadCloud className="h-4 w-4" />
                  {uploading ? "Encrypting Stream..." : "Upload File Asset"}
                </label>
              </div>
            </div>

            {selectedProject.vault.length === 0 ? (
              <div className="text-center py-8 border border-dashed border-white/10 rounded-xl text-gray-600 text-xs">
                No payloads, binary logs, or evidence mapped to this vault structure yet.
              </div>
            ) : (
              <div className="overflow-hidden border border-white/5 bg-black/20 rounded-xl divide-y divide-white/5">
                {selectedProject.vault.map((item) => (
                  <div key={item.id} className="flex items-center justify-between p-4 hover:bg-white/[0.01] transition">
                    <div 
                      onClick={() => handleFileDownload(item.id)}
                      className="flex items-center gap-3 overflow-hidden cursor-pointer group/file"
                    >
                      <IconDocFile className="h-5 w-5 text-cyan-400 shrink-0 group-hover/file:text-emerald-400 transition-colors" />
                      <div className="overflow-hidden">
                        <p className="text-gray-200 font-medium truncate text-xs group-hover/file:text-white group-hover/file:underline decoration-emerald-400 transition-all">
                          {item.name}
                        </p>
                        <p className="text-[10px] text-gray-500 mt-0.5">{item.size} • Buffered {item.date}</p>
                      </div>
                    </div>
                    <button onClick={() => handleVaultDelete(item.id)} className="text-gray-500 hover:text-red-400 p-2 border-none bg-transparent cursor-pointer transition">
                      <IconTrashCan className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === "account" && <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6"><p>Identity: <span className="text-white">{username}</span></p></div>}
      {activeTab === "settings" && <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6"><p className="text-xs text-gray-500">Global directives menu.</p></div>}
    </div>
  );
}

function Footer() { return <footer className="border-t border-white/10 px-6 py-10 text-center text-sm text-gray-500"><p>© {new Date().getFullYear()} ITEK. All rights reserved.</p></footer>; }

export default function App() {
  const [activeUser, setActiveUser] = useState(() => localStorage.getItem("itek_user") || null);
  const [view, setView] = useState(() => localStorage.getItem("itek_user") ? "dashboard" : "landing");

  const navigateTo = (targetView) => { setView(targetView); };
  const handleLoginSuccess = (user) => { localStorage.setItem("itek_user", user); setActiveUser(user); navigateTo("dashboard"); };
  const handleLogout = () => { localStorage.removeItem("itek_user"); setActiveUser(null); navigateTo("landing"); };

  return (
    <div className="min-h-screen bg-black font-sans text-gray-100 antialiased">
      <Navbar setView={navigateTo} view={activeUser ? "dashboard" : view} />
      {activeUser ? (
        <DashboardView username={activeUser} onLogout={handleLogout} />
      ) : view === "landing" ? (
        <>
          <Hero setView={navigateTo} />
          <Capabilities />
          <TerminalDemo />
        </>
      ) : (
        <AuthPage view={view} setView={navigateTo} onLoginSuccess={handleLoginSuccess} />
      )}
      <Footer />
    </div>
  );
}