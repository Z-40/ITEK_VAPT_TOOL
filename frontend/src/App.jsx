import { useState, useEffect, useRef } from "react";

function IconRadar({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}><circle cx="12" cy="12" r="9" strokeOpacity="0.9" /><circle cx="12" cy="12" r="5" strokeOpacity="0.5" /><path d="M12 12V4" strokeLinecap="round" /><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" /></svg>; }
function IconBracket({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M9 18 5 12 9 6" /><path d="M15 6l4 6-4 6" /></svg>; }
function IconShieldCheck({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M12 3l7 3v6c0 5-3.2 7.8-7 9-3.8-1.2-7-4-7-9V6z" /><path d="M9 12.2l2 2 4-4.4" /></svg>; }
function IconBug({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M9 7V5a3 3 0 0 1 6 0v2" /><rect x="6" y="7" width="12" height="11" rx="5.5" /><path d="M6 12H3M21 12h-3M8 4 6 2M16 4l2-2M9 18l-2 2M15 18l2 2" /></svg>; }
function IconTarget({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="0.8" fill="currentColor" stroke="none" /><path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3" strokeLinecap="round" /></svg>; }
function IconLockBox({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>; }
function IconUploadCloud({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12" /></svg>; }
function IconDocFile({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>; }
function IconTrashCan({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /></svg>; }
function IconGlobe({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><circle cx="12" cy="12" r="10" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /><path d="M2 12h20" /></svg>; }
function IconFlame({ className }) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" /></svg>; }

const NAV_LINKS = [{ href: "#capabilities", label: "Capabilities" }, { href: "#demo", label: "Live demo" }, { href: "#", label: "Docs" }];

const FEATURES = [
  { n: "01", cmd: "itek recon --target acme.io", title: "Recon", desc: "Map subdomains, DNS records, open ports, and service fingerprints before touching an endpoint.", icon: IconRadar },
  { n: "02", cmd: "itek inject --engine sqlmap+", title: "SQL Injection", desc: "Boolean, time-based, and union-based injection testing across every form parameters and API field.", icon: IconBracket },
  { n: "03", cmd: "itek match --cve-db nightly", title: "CVE Detection", desc: "Cross-reference fingerprinted targets against a nightly-updated feed to isolate exploitable versions.", icon: IconShieldCheck },
  { n: "04", cmd: "itek DAST --crawl-depth 5", title: "DAST Engine", desc: "Crawl and fuzz operational infrastructure workflows for authentication bypasses, XSS, and IDOR vulnerabilities.", icon: IconBug },
  { n: "05", cmd: "itek exploit --confirm-only", title: "Exploitation Matrix", desc: "Verify active vectors with secure confirm-only payloads to eliminate false positives cleanly.", icon: IconTarget },
];

const PRE_FLIGHT_DEMO_LINES = [
  { type: "cmd", text: "itek scan --target pipeline-scope --mode full" },
  { type: "log", text: "[00:01] mapping targeted domain scopes" },
  { type: "log", text: "[00:03] analyzing uploaded configuration parameters" },
  { type: "log", text: "[00:06] parsing bounded OpenAPI/Swagger route paths" },
  { type: "log", text: "[00:11] initializing fuzzing matrices" },
  { type: "critical", text: "[ALERT] core router endpoint parameter manipulation verified" },
  { type: "high", text: "[ALERT] path traversal leakage detected on sub-route structures" },
  { type: "log", text: "[00:19] writing dynamic logging traces into repository vault" },
  { type: "done", text: "Scan execution segment finished. Structural output complete." },
];

function Navbar({ setView, view }) {
  const [open, setOpen] = useState(false);
  const handleNavClick = (viewName) => { setView(viewName); setOpen(false); };

  return (
    <nav className="fixed inset-x-0 top-0 z-50 border-b border-white/10 bg-black/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <button onClick={() => handleNavClick(localStorage.getItem("itek_user") ? "dashboard" : "landing")} className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-400 font-mono text-sm font-bold text-black">I</span>
          <span className="font-mono text-lg font-bold tracking-tight text-white">ITEK</span>
        </button>
        <div className="flex items-center gap-6">
          {view === "dashboard" && <span className="text-emerald-400 font-mono text-xs">Secured Management Portal</span>}
          {view !== "dashboard" && (
            <button onClick={() => setView("landing")} className="text-gray-400 hover:text-white">← Back</button>
          )}
        </div>
      </div>
    </nav>
  );
}

function Hero({ setView }) { /* your hero code */ }
function Capabilities() { /* your capabilities code */ }
function TerminalDemo() { /* fixed version from previous message */ }
function AuthPage({ view, setView, onLoginSuccess }) { /* your auth code */ }

function DashboardView({ username, onLogout }) {
  const [activeTab, setActiveTab] = useState("projects");
  const [profileData, setProfileData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`http://127.0.0.1:8000/${username}`)
      .then(res => res.json())
      .then(data => {
        setProfileData(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [username]);

  if (loading) return <div className="pt-40 text-center text-xl text-gray-400">Loading Dashboard...</div>;

  return (
    <div className="pt-24 px-6">
      <h1 className="text-4xl font-bold text-white mb-8">Welcome back, {profileData?.username || username}</h1>
      <div className="bg-zinc-900 border border-white/10 rounded-2xl p-8">
        <p className="text-emerald-400 text-lg">Dashboard is now working.</p>
        <p className="text-gray-400 mt-4">Add your tabs and project content here.</p>
      </div>
    </div>
  );
}

function Footer() { return <footer className="py-8 text-center text-gray-500 text-sm">© 2026 ITEK. All rights reserved.</footer>; }

export default function App() {
  const [activeUser, setActiveUser] = useState(() => localStorage.getItem("itek_user") || null);
  const [view, setView] = useState("landing");

  const handleLoginSuccess = (user) => {
    localStorage.setItem("itek_user", user);
    setActiveUser(user);
    setView("dashboard");
  };

  const handleLogout = () => {
    localStorage.removeItem("itek_user");
    setActiveUser(null);
    setView("landing");
  };

  return (
    <div className="min-h-screen bg-black text-white">
      <Navbar setView={setView} view={view} />
      {activeUser ? (
        <DashboardView username={activeUser} onLogout={handleLogout} />
      ) : view === "landing" ? (
        <>
          <Hero setView={setView} />
          <Capabilities />
          <TerminalDemo />
        </>
      ) : (
        <AuthPage view={view} setView={setView} onLoginSuccess={handleLoginSuccess} />
      )}
      <Footer />
    </div>
  );
}