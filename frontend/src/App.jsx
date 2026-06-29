import { useState, useEffect } from "react";

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

function IconEye({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function IconEyeOff({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-10-7-10-7a19.08 19.08 0 0 1 4.39-4.39M1 1l22 22M9 9a3 3 0 1 0 4.24 4.24" />
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

function IconMenu({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" className={className}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  );
}

function IconClose({ className }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" className={className}>
      <path d="M6 6l12 12M18 6 6 18" />
    </svg>
  );
}

/* ---------------------------------------------------------------- */
/* Data Context Blocks                                              */
/* ---------------------------------------------------------------- */

const NAV_LINKS = [
  { href: "#capabilities", label: "Capabilities" },
  { href: "#demo", label: "Live demo" },
  { href: "#", label: "Docs" },
];

const FEATURES = [
  {
    n: "01",
    cmd: "itek recon --target acme.io",
    title: "Recon",
    desc: "Map subdomains, DNS records, open ports, and service fingerprints before touching a single endpoint.",
    icon: IconRadar,
  },
  {
    n: "02",
    cmd: "itek inject --engine sqlmap+",
    title: "SQL Injection",
    desc: "Boolean, time-based, and union-based injection testing across every parameter, form, and API field.",
    icon: IconBracket,
  },
  {
    n: "03",
    cmd: "itek match --cve-db nightly",
    title: "CVE Detection",
    desc: "Cross-reference fingerprinted services against a nightly-updated CVE feed and flag exploitable versions.",
    icon: IconShieldCheck,
  },
  {
    n: "04",
    cmd: "itek dast --crawl-depth 5",
    title: "DAST",
    desc: "Crawl and fuzz live application logic for XSS, auth bypass, IDOR, and business-logic flaws.",
    icon: IconBug,
  },
  {
    n: "05",
    cmd: "itek exploit --confirm-only",
    title: "Automated Exploitation",
    desc: "Validate exploitability with confirm-only payloads and proof-of-concept evidence, not guesswork.",
    icon: IconTarget,
  },
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

const SEVERITY_STYLES = {
  critical: "border-red-500/30 bg-red-500/15 text-red-400",
  high: "border-orange-500/30 bg-orange-500/15 text-orange-400",
  medium: "border-amber-500/30 bg-amber-500/15 text-amber-400",
  done: "border-emerald-500/30 bg-emerald-500/15 text-emerald-400",
};

/* ---------------------------------------------------------------- */
/* Layout Structure Components                                      */
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
        <button onClick={() => handleNavClick(localStorage.getItem("itek_user") ? "dashboard" : "landing")} className="flex items-center gap-2.5 bg-transparent border-none outline-none cursor-pointer">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-400 font-mono text-sm font-bold text-black">
            I
          </span>
          <span className="font-mono text-lg font-bold tracking-tight text-white">ITEK</span>
        </button>

        <div className="items-center gap-8 text-sm text-gray-400 flex">
          {view === "landing" ? (
            <div className="hidden gap-8 md:flex">
              {NAV_LINKS.map((link) => (
                <a key={link.label} href={link.href} className="transition-colors hover:text-white">
                  {link.label}
                </a>
              ))}
            </div>
          ) : view !== "dashboard" ? (
            <button 
              onClick={() => handleNavClick("landing")} 
              className="transition-colors hover:text-white text-sm text-gray-400 bg-transparent border-none outline-none cursor-pointer"
            >
              ← Back to Home
            </button>
          ) : (
            <span className="text-emerald-400 font-mono text-xs">Secured Management Portal</span>
          )}
        </div>

        {view !== "dashboard" && (
          <div className="hidden items-center gap-3 md:flex">
            <button 
              onClick={() => handleNavClick("login")}
              className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/60 ${view === 'login' ? 'text-emerald-400' : 'text-gray-300 hover:text-white'}`}
            >
              Log in
            </button>
            <button 
              onClick={() => handleNavClick("signup")}
              className="rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-sm font-semibold text-black transition hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/60"
            >
              Sign up
            </button>
          </div>
        )}

        {view !== "dashboard" && (
          <button
            onClick={() => setOpen((v) => !v)}
            className="text-gray-300 md:hidden"
            aria-label={open ? "Close menu" : "Open menu"}
          >
            {open ? <IconClose className="h-6 w-6" /> : <IconMenu className="h-6 w-6" />}
          </button>
        )}
      </div>

      {open && view !== "dashboard" && (
        <div className="border-t border-white/10 bg-black/95 px-6 py-5 md:hidden">
          <div className="flex flex-col gap-4 text-sm text-gray-300">
            {view === "landing" && NAV_LINKS.map((link) => (
              <a key={link.label} href={link.href} onClick={() => setOpen(false)} className="hover:text-white">
                {link.label}
              </a>
            ))}
            <div className="mt-2 flex flex-col gap-3 border-t border-white/10 pt-4">
              <button onClick={() => handleNavClick("login")} className="rounded-lg border border-white/15 px-4 py-2.5 text-sm font-medium text-gray-200">Log in</button>
              <button onClick={() => handleNavClick("signup")} className="rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2.5 text-sm font-semibold text-black">Sign up</button>
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
      <div className="pointer-events-none absolute -left-40 -top-40 h-[480px] w-[480px] rounded-full bg-emerald-500/20 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-40 -right-40 h-[480px] w-[480px] rounded-full bg-cyan-500/20 blur-3xl" />
      <div className="relative z-10 mx-auto max-w-4xl text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/5 px-4 py-1.5 font-mono text-xs uppercase tracking-[0.2em] text-emerald-400">Offensive Security Platform</span>
        <h1 className="mt-8 font-mono text-5xl font-bold leading-[1.05] tracking-tight text-white sm:text-6xl lg:text-7xl">Attack your own<br /><span className="bg-gradient-to-r from-emerald-300 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">infrastructure first.</span></h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-gray-400 sm:text-xl">ITEK automates recon, exploitation, and CVE correlation across your entire attack surface — so the next intrusion attempt finds nothing left to take.</p>
        <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row"><button onClick={() => setView("signup")} className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-8 py-3.5 text-sm font-semibold text-black transition hover:brightness-110 focus:outline-none">Start a free assessment</button><a href="#demo" className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/15 px-8 py-3.5 text-sm font-semibold text-gray-200 transition hover:border-emerald-400/50 hover:text-white focus:outline-none">Watch a live engagement →</a></div>
      </div>
    </section>
  );
}

function Capabilities() {
  return (
    <section id="capabilities" className="mx-auto max-w-7xl px-6 py-24">
      <div className="mb-14 max-w-2xl"><span className="font-mono text-xs uppercase tracking-widest text-emerald-400">Capabilities</span><h2 className="mt-3 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">Five stages. One pipeline.</h2><p className="mt-4 text-gray-400">Every engagement runs the same disciplined sequence — from first DNS lookup to confirmed exploit.</p></div>
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f) => (
          <div key={f.n} className="group relative rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition-all duration-300 hover:border-emerald-400/40 hover:bg-white/[0.04]">
            <div className="mb-5 flex items-center justify-between"><div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 group-hover:bg-emerald-500/20"><f.icon className="h-5 w-5" /></div><span className="font-mono text-xs text-gray-600">{f.n}</span></div>
            <p className="mb-2 truncate font-mono text-[11px] text-cyan-400/80">$ {f.cmd}</p><h3 className="mb-2 text-lg font-semibold text-white">{f.title}</h3><p className="text-sm leading-relaxed text-gray-400">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function TerminalDemo() {
  const [visibleCount, setVisibleCount] = useState(0);
  useEffect(() => {
    const id = setInterval(() => { setVisibleCount((c) => (c >= SCAN_LINES.length + 4 ? 0 : c + 1)); }, 450);
    return () => clearInterval(id);
  }, []);
  const shown = SCAN_LINES.slice(0, Math.min(visibleCount, SCAN_LINES.length));
  return (
    <section id="demo" className="bg-gradient-to-b from-transparent via-emerald-500/[0.03] to-transparent px-6 py-24">
      <div className="mx-auto mb-12 max-w-3xl text-center"><span className="font-mono text-xs uppercase tracking-widest text-cyan-400">Live engagement preview</span><h2 className="mt-3 font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">Watch ITEK work in real time</h2></div>
      <div className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-white/10 bg-zinc-950/80 shadow-2xl backdrop-blur-xl">
        <div className="flex items-center gap-2 border-b border-white/10 bg-white/[0.02] px-4 py-3"><span className="h-3 w-3 rounded-full bg-red-500/70" /><span className="h-3 w-3 rounded-full bg-amber-500/70" /><span className="h-3 w-3 rounded-full bg-emerald-500/70" /><span className="mx-auto font-mono text-xs text-gray-500">itek — engagement/acme-corp.io</span></div>
        <div className="min-h-[360px] p-6 font-mono text-[13px] leading-relaxed sm:text-sm">
          {shown.map((line, i) => {
            if (line.type === "cmd") return <p key={i} className="text-gray-200"><span className="text-emerald-400">itek@core</span><span className="text-gray-500">:~$ </span>{line.text}</p>;
            if (line.type === "log") return <p key={i} className="text-gray-500">{line.text}</p>;
            return <p key={i} className="flex flex-wrap items-baseline gap-2 py-0.5"><span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${SEVERITY_STYLES[line.type]}`}>{line.type.toUpperCase()}</span><span className="text-gray-300">{line.text}</span></p>;
          })}
          <span className="mt-1 inline-block h-4 w-2 bg-emerald-400/80 align-middle animate-pulse" />
        </div>
      </div>
    </section>
  );
}

function CTABand({ setView }) {
  return (
    <section className="px-6 py-20">
      <div className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-emerald-500/10 via-transparent to-cyan-500/10 p-10 text-center sm:p-14">
        <h2 className="relative font-mono text-3xl font-bold tracking-tight text-white sm:text-4xl">Your attack surface is already being scanned.</h2>
        <button onClick={() => setView("signup")} className="relative mt-8 inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-8 py-3.5 text-sm font-semibold text-black transition hover:brightness-110 focus:outline-none">Start your assessment</button>
      </div>
    </section>
  );
}

/* ---------------------------------------------------------------- */
/* Auth Page Component (Fully Operational API Pipeline)            */
/* ---------------------------------------------------------------- */

function AuthPage({ view, setView, onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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

      if (!response.ok) {
        throw new Error(data.detail || "Authentication request rejected.");
      }

      if (view === "login") {
        onLoginSuccess(data.username);
      } else {
        alert("Registration complete! Please use your credentials to log in.");
        setView("login");
      }

      setEmail("");
      setUsername("");
      setPassword("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="relative flex min-h-[calc(100vh-4rem)] items-center justify-center px-6 pt-24 pb-12">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-zinc-950/70 p-8 shadow-2xl backdrop-blur-xl">
        <div className="mb-8 text-center">
          <span className="font-mono text-xs uppercase tracking-widest text-emerald-400">{view === "login" ? "Welcome Back" : "Get Started"}</span>
          <h2 className="mt-2 font-mono text-2xl font-bold tracking-tight text-white">{view === "login" ? "Log In" : "Create Account"}</h2>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {error && <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-center font-mono text-xs text-red-400">{error}</div>}

          {view === "signup" && (
            <div>
              <label className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-2">Username</label>
              <input type="text" required disabled={loading} placeholder="sec_operator" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 font-mono text-sm text-white placeholder-gray-600 outline-none transition focus:border-emerald-400/40 focus:ring-1 focus:ring-emerald-400/40 disabled:opacity-50" />
            </div>
          )}

          <div>
            <label className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-2">Email</label>
            <input type="email" required disabled={loading} placeholder="name@example.com" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 font-mono text-sm text-white placeholder-gray-600 outline-none transition focus:border-emerald-400/40 focus:ring-1 focus:ring-emerald-400/40 disabled:opacity-50" />
          </div>

          <div>
            <label className="block font-mono text-xs text-gray-400 uppercase tracking-wider mb-2">Password</label>
            <div className="relative">
              <input type={showPassword ? "text" : "password"} required disabled={loading} placeholder="••••••••••••" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-xl border border-white/10 bg-white/[0.02] pl-4 pr-11 py-3 font-mono text-sm text-white placeholder-gray-600 outline-none transition focus:border-emerald-400/40 focus:ring-1 focus:ring-emerald-400/40 disabled:opacity-50" />
              <button type="button" onClick={() => setShowPassword(!showPassword)} disabled={loading} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 disabled:opacity-50">{showPassword ? <IconEyeOff className="h-4 w-4" /> : <IconEye className="h-4 w-4" />}</button>
            </div>
          </div>

          <button type="submit" disabled={loading} className="w-full rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-3.5 font-mono text-sm font-bold text-black transition hover:brightness-110 focus:outline-none disabled:opacity-50">
            {loading ? "Processing..." : (view === "login" ? "Log In" : "Sign Up")}
          </button>
        </form>

        <div className="mt-6 border-t border-white/5 pt-4 text-center font-mono text-xs text-gray-500">
          {view === "login" ? (
            <p>New user? <button onClick={() => { setView("signup"); setError(null); }} disabled={loading} className="text-emerald-400 hover:underline bg-transparent border-none p-0 cursor-pointer disabled:opacity-50">Sign up</button></p>
          ) : (
            <p>Already have an account? <button onClick={() => { setView("login"); setError(null); }} disabled={loading} className="text-emerald-400 hover:underline bg-transparent border-none p-0 cursor-pointer disabled:opacity-50">Log in</button></p>
          )}
        </div>
      </div>
    </section>
  );
}

/* ---------------------------------------------------------------- */
/* Dashboard View Component (GitHub Style Space Workspace)          */
/* ---------------------------------------------------------------- */

function DashboardView({ username, onLogout }) {
  const [activeTab, setActiveTab] = useState("projects");
  const [profileData, setProfileData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [projectFilter, setProjectFilter] = useState("");
  const [selectedProject, setSelectedProject] = useState(null);

  useEffect(() => {
    fetch(`http://127.0.0.1:8000/${username}`)
      .then((res) => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then((data) => {
        setProfileData(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [username]);

  const handleProjectClick = async (projectName) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/${username}/${projectName}`);
      const data = await res.json();
      setSelectedProject(data);
      setActiveTab("project-detail");
    } catch (err) {
      alert("Error isolating target namespace profile specifications.");
    }
  };

  if (loading) return <div className="pt-32 text-center font-mono text-gray-500">Decrypting workspace environments...</div>;
  if (!profileData) return <div className="pt-32 text-center font-mono text-red-400">Security Clearance Violation: Could not load target nodes.</div>;

  const filteredProjects = profileData.projects.filter(p => p.name.toLowerCase().includes(projectFilter.toLowerCase()));

  return (
    <div className="mx-auto max-w-7xl px-6 pt-24 pb-16 font-mono text-sm text-gray-300">
      <div className="flex flex-col items-start gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{profileData.username}</h1>
          <p className="text-gray-500 mt-1">{profileData.role} @ <span className="text-emerald-400">{profileData.company}</span></p>
        </div>
        <button onClick={onLogout} className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs font-bold text-red-400 hover:bg-red-500/20 transition">Sign Out</button>
      </div>

      <div className="flex gap-6 border-b border-white/10 my-6 text-xs uppercase tracking-wider">
        {["overview", "projects", "account", "settings"].map((tab) => (
          <button key={tab} onClick={() => { setActiveTab(tab); setSelectedProject(null); }} className={`pb-3 font-bold transition bg-transparent border-none outline-none cursor-pointer ${activeTab === tab ? "border-b-2 border-emerald-400 text-white" : "text-gray-500 hover:text-gray-300"}`}>
            {tab} {tab === "projects" && `(${profileData.projects.length})`}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="space-y-4 border border-white/10 bg-zinc-950/40 rounded-xl p-6">
          <h3 className="text-white text-base">Operator Biography Overview</h3>
          <p className="text-gray-400 text-xs leading-relaxed">{profileData.bio}</p>
        </div>
      )}

      {activeTab === "projects" && (
        <div className="space-y-4">
          <div className="flex gap-3"><input type="text" placeholder="Search operational targets..." value={projectFilter} onChange={(e) => setProjectFilter(e.target.value)} className="w-full max-w-md rounded-xl border border-white/10 bg-white/[0.02] px-4 py-2 text-xs text-white outline-none focus:border-emerald-400/40" /></div>
          <div className="divide-y divide-white/10 border-t border-b border-white/10">
            {filteredProjects.map((project) => (
              <div key={project.name} className="flex items-center justify-between py-4 hover:bg-white/[0.01] px-2 transition rounded-lg">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <button onClick={() => handleProjectClick(project.name)} className="text-base font-bold text-emerald-400 hover:underline bg-transparent border-none p-0 text-left cursor-pointer">{project.name}</button>
                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] text-gray-500">{project.visibility}</span>
                  </div>
                  <div className="flex gap-4 text-xs">
                    {project.critical > 0 && <span className="text-red-400 font-bold">● {project.critical} Critical</span>}
                    {project.high > 0 && <span className="text-orange-400 font-bold">● {project.high} High</span>}
                    {project.critical === 0 && project.high === 0 && <span className="text-emerald-500">● Safe</span>}
                    <span className="text-gray-600">Sync profile {project.updated}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "project-detail" && selectedProject && (
        <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6 space-y-4">
          <button onClick={() => setActiveTab("projects")} className="text-xs text-gray-500 hover:text-white cursor-pointer bg-transparent border-none">← Back to projects list</button>
          <h3 className="text-white text-lg font-bold">{selectedProject.project_info.name} Engine Scope</h3>
          <p className="text-xs text-gray-400">Target Range Configuration Mappings:</p>
          <pre className="bg-black/50 p-3 rounded border border-white/5 text-xs text-cyan-400">{JSON.stringify(selectedProject.scope_rules, null, 2)}</pre>
          <p className="text-xs text-gray-400">Automation Engine State: <span className="text-emerald-400">{selectedProject.engine_status}</span></p>
        </div>
      )}

      {activeTab === "account" && (
        <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6 space-y-4">
          <h3 className="text-white text-base">Security Clearance Identity</h3>
          <div className="space-y-2 text-xs text-gray-400">
            <p>Assigned Workspace System ID: <span className="text-white">{username}</span></p>
            <p>Access Clearance Group Policy: <span className="text-white">{profileData.role}</span></p>
          </div>
        </div>
      )}

      {activeTab === "settings" && (
        <div className="border border-white/10 bg-zinc-950/40 rounded-xl p-6 space-y-4">
          <h3 className="text-white text-base">Global Engine Directives</h3>
          <p className="text-xs text-gray-500">Enable automated nightly threat monitoring updates on target ranges.</p>
          <button className="rounded-lg bg-emerald-400 px-4 py-2 text-xs font-bold text-black hover:brightness-110 transition cursor-pointer">Save Configurations</button>
        </div>
      )}
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t border-white/10 px-6 py-10">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 text-sm text-gray-500 sm:flex-row">
        <div className="flex items-center gap-2.5"><span className="flex h-6 w-6 items-center justify-center rounded bg-gradient-to-br from-emerald-400 to-cyan-400 font-mono text-xs font-bold text-black">I</span><span className="font-mono font-semibold text-gray-300">ITEK</span></div>
        <p>© {new Date().getFullYear()} ITEK. All rights reserved.</p>
      </div>
    </footer>
  );
}

/* ---------------------------------------------------------------- */
/* App Component Core Engine Hub                                    */
/* ---------------------------------------------------------------- */

export default function App() {
  const [activeUser, setActiveUser] = useState(() => localStorage.getItem("itek_user") || null);
  const [view, setView] = useState(() => {
    if (localStorage.getItem("itek_user")) return "dashboard";
    const path = window.location.pathname;
    if (path === "/login") return "login";
    if (path === "/signup") return "signup";
    return "landing";
  });

  useEffect(() => {
    const handlePopState = () => {
      if (localStorage.getItem("itek_user")) {
        setView("dashboard");
        return;
      }
      const path = window.location.pathname;
      if (path === "/login") setView("login");
      else if (path === "/signup") setView("signup");
      else setView("landing");
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigateTo = (targetView) => {
    const path = targetView === "landing" || targetView === "dashboard" ? "/" : `/${targetView}`;
    window.history.pushState(null, "", path);
    setView(targetView);
  };

  const handleLoginSuccess = (username) => {
    localStorage.setItem("itek_user", username);
    setActiveUser(username);
    navigateTo("dashboard");
  };

  const handleLogout = () => {
    localStorage.removeItem("itek_user");
    setActiveUser(null);
    navigateTo("landing");
  };

  useEffect(() => { window.scrollTo(0, 0); }, [view]);

  return (
    <div className="min-h-screen overflow-x-hidden bg-black font-sans text-gray-100 antialiased selection:bg-emerald-500/30">
      <Navbar setView={navigateTo} view={activeUser ? "dashboard" : view} />
      
      {activeUser || view === "dashboard" ? (
        <DashboardView username={activeUser || "admin"} onLogout={handleLogout} />
      ) : view === "landing" ? (
        <>
          <Hero setView={navigateTo} />
          <Capabilities />
          <TerminalDemo />
          <CTABand setView={navigateTo} />
        </>
      ) : (
        <AuthPage view={view} setView={navigateTo} onLoginSuccess={handleLoginSuccess} />
      )}
      
      <Footer />
    </div>
  );
}