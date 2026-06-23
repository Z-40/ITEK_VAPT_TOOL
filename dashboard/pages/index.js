import { useState, useEffect, useRef } from 'react'
import Head from 'next/head'

// ─── Data ──────────────────────────────────────────────────────────────────────

const MODULES = [
  {
    id: 'recon',
    badge: 'RECON',
    name: 'Reconnaissance',
    color: '#4E9AF1',
    dimColor: 'rgba(78, 154, 241, 0.12)',
    glowColor: 'rgba(78, 154, 241, 0.22)',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        <line x1="11" y1="8" x2="11" y2="14"/>
        <line x1="8" y1="11" x2="14" y2="11"/>
      </svg>
    ),
    description: 'Full-spectrum information gathering: DNS records, WHOIS intelligence, port scanning, subdomain enumeration, and technology fingerprinting.',
    capabilities: [
      'DNS enumeration — A, MX, NS, TXT, CNAME',
      'WHOIS domain intelligence lookup',
      'Nmap port scanning & service detection',
      'Subdomain brute-force via Sublist3r',
      'Technology fingerprinting with BuiltWith',
      'Google dorking through SerpAPI',
    ],
    deps: ['dnspython', 'python-whois', 'python-nmap', 'sublist3r', 'builtwith', 'aiohttp'],
  },
  {
    id: 'sqli',
    badge: 'SQLI',
    name: 'SQL Injection',
    color: '#FF2D78',
    dimColor: 'rgba(255, 45, 120, 0.12)',
    glowColor: 'rgba(255, 45, 120, 0.22)',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"/>
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
        <line x1="9" y1="9" x2="15" y2="15"/>
        <line x1="15" y1="9" x2="9" y2="15"/>
      </svg>
    ),
    description: 'Automated SQL injection detection across web endpoints — error-based, blind, time-based, and authentication bypass payloads.',
    capabilities: [
      'Error-based SQLi detection',
      'Blind injection testing with boolean logic',
      'Time-based payload analysis',
      'POST parameter fuzzing',
      'Authentication bypass attempts',
      'Async multi-endpoint batch scanning',
    ],
    deps: ['aiohttp', 'aiofiles', 'requests', 'beautifulsoup4'],
  },
  {
    id: 'cve_dast',
    badge: 'CVE/DAST',
    name: 'CVE & DAST',
    color: '#FFB830',
    dimColor: 'rgba(255, 184, 48, 0.12)',
    glowColor: 'rgba(255, 184, 48, 0.22)',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    ),
    description: 'Dynamic Application Security Testing paired with CVE database cross-referencing for known vulnerability matching and CVSS scoring.',
    capabilities: [
      'CVE database cross-referencing',
      'Dynamic vulnerability assessment (DAST)',
      'CVSS v3 severity scoring',
      'Service fingerprint to CVE mapping',
      'Exploitability chain analysis',
      'Async concurrent target scanning',
    ],
    deps: ['requests', 'aiohttp', 'python-dotenv', 'ratelimit'],
  },
  {
    id: 'post_requests',
    badge: 'POST',
    name: 'POST Analysis',
    color: '#00F5A0',
    dimColor: 'rgba(0, 245, 160, 0.12)',
    glowColor: 'rgba(0, 245, 160, 0.22)',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <line x1="22" y1="2" x2="11" y2="13"/>
        <polygon points="22 2 15 22 11 13 2 9 22 2"/>
      </svg>
    ),
    description: 'Deep inspection and fuzzing of POST request parameters, authentication headers, CORS policies, and request body payloads.',
    capabilities: [
      'Header injection & manipulation',
      'Content-Type boundary testing',
      'Auth token analysis & replay attacks',
      'CORS misconfiguration detection',
      'Rate limit bypass testing',
      'Async batch request flooding',
    ],
    deps: ['requests', 'aiohttp', 'aiofiles', 'ratelimit', 'urllib3'],
  },
  {
    id: 'tls_config',
    badge: 'TLS',
    name: 'TLS Configuration',
    color: '#B55CF5',
    dimColor: 'rgba(181, 92, 245, 0.12)',
    glowColor: 'rgba(181, 92, 245, 0.22)',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        <circle cx="12" cy="16" r="1"/>
      </svg>
    ),
    description: 'In-depth SSL/TLS certificate and cipher suite analysis to surface cryptographic misconfigurations and protocol weaknesses.',
    capabilities: [
      'Certificate chain & validity analysis',
      'Cipher suite enumeration',
      'BEAST / POODLE attack surface detection',
      'TLS 1.0/1.1 deprecation checks',
      'Certificate expiry monitoring',
      'HSTS header & pinning verification',
    ],
    deps: ['sslyze', 'certifi', 'urllib3', 'aiohttp'],
  },
]

const TERMINAL_LINES = [
  { text: '$ itek-vapt --target target.example.com --full-scan', type: 'cmd' },
  { text: '[*] Initializing ITEK VAPT Suite v2.0...', type: 'info' },
  { text: '[*] Target: target.example.com  |  Modules: ALL', type: 'info' },
  { text: '', type: 'blank' },
  { text: '[>] MODULE: RECON ─────────────────────────────', type: 'module' },
  { text: '    ├── DNS Records: A, MX, TXT, NS found (14)', type: 'result' },
  { text: '    ├── WHOIS: registrar, ASN, org resolved', type: 'result' },
  { text: '    ├── Subdomains: 8 active discovered', type: 'result' },
  { text: '    └── Open Ports: 22, 80, 443, 8080 detected', type: 'result' },
  { text: '', type: 'blank' },
  { text: '[>] MODULE: TLS_CONFIG ────────────────────────', type: 'module' },
  { text: '    ├── Certificate: RSA-2048, valid 89 days', type: 'result' },
  { text: '    ├── TLS 1.3 supported', type: 'result' },
  { text: '    └── ⚠  BEAST attack surface detected (TLS 1.0)', type: 'warn' },
  { text: '', type: 'blank' },
  { text: '[>] MODULE: CVE_DAST ──────────────────────────', type: 'module' },
  { text: '    ├── CVE-2024-6387 (OpenSSH RCE) — CRITICAL', type: 'critical' },
  { text: '    └── 15 CVEs scanned, 1 matched', type: 'result' },
  { text: '', type: 'blank' },
  { text: '[>] MODULE: SQLI ──────────────────────────────', type: 'module' },
  { text: '    ├── 12 endpoints tested', type: 'result' },
  { text: '    └── ⚠  2 injection vectors found', type: 'warn' },
  { text: '', type: 'blank' },
  { text: '[>] MODULE: POST_REQUESTS ─────────────────────', type: 'module' },
  { text: '    └── CORS header misconfiguration detected', type: 'warn' },
  { text: '', type: 'blank' },
  { text: '[+] Report generated: report_20260623.pdf', type: 'success' },
  { text: '[+] Scan complete in 3m 42s', type: 'success' },
  { text: '    CRITICAL: 1  │  MEDIUM: 2  │  LOW: 1', type: 'success' },
]

const STATS = [
  { value: '5', label: 'Security Modules' },
  { value: '35+', label: 'Python Libraries' },
  { value: '4', label: 'Export Formats' },
  { value: '100%', label: 'Python 3.10+' },
]

const STACK_GROUPS = [
  {
    label: 'Core Recon',
    color: '#4E9AF1',
    items: ['dnspython', 'python-whois', 'python-nmap', 'sublist3r', 'builtwith'],
  },
  {
    label: 'HTTP & Async',
    color: '#00F5A0',
    items: ['requests', 'aiohttp', 'aiofiles', 'urllib3', 'beautifulsoup4'],
  },
  {
    label: 'TLS & Security',
    color: '#B55CF5',
    items: ['sslyze', 'certifi', 'ratelimit'],
  },
  {
    label: 'Reporting',
    color: '#FFB830',
    items: ['pandas', 'jinja2', 'weasyprint', 'openpyxl'],
  },
  {
    label: 'CLI & Config',
    color: '#FF2D78',
    items: ['click', 'rich', 'colorama', 'python-dotenv'],
  },
  {
    label: 'Advanced',
    color: '#00E5D4',
    items: ['google-search-results', 'requests[socks]', 'pytest', 'black'],
  },
]

const INSTALL_CODE = `git clone https://github.com/Z-40/ITEK_VAPT_TOOL
cd ITEK_VAPT_TOOL
pip install -r requirements.txt`

const SCAN_CODE = `# Full scan against a target
python main.py --target target.com --full-scan

# Run specific modules
python main.py --target target.com --modules recon,sqli,tls

# Export report as PDF
python main.py --target target.com --output pdf`

// ─── Components ─────────────────────────────────────────────────────────────────

function Terminal({ lines }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  const lineColor = (type) => {
    if (type === 'cmd')      return '#00E5D4'
    if (type === 'info')     return '#6B88A8'
    if (type === 'module')   return '#4E9AF1'
    if (type === 'result')   return '#C8D8E8'
    if (type === 'warn')     return '#FFB830'
    if (type === 'critical') return '#FF2D78'
    if (type === 'success')  return '#00F5A0'
    return '#3D5470'
  }

  return (
    <div className="terminal">
      <div className="terminal-header">
        <div className="terminal-dots">
          <span className="dot dot-red" />
          <span className="dot dot-yellow" />
          <span className="dot dot-green" />
        </div>
        <span className="terminal-title">itek-vapt — zsh</span>
      </div>
      <div className="terminal-body">
        {lines.map((line, i) => (
          <div
            key={i}
            className="terminal-line"
            style={{ color: lineColor(line.type), animationDelay: `0ms` }}
          >
            {line.text || '\u00A0'}
          </div>
        ))}
        <span className="cursor">█</span>
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

function ModuleCard({ module }) {
  return (
    <div className="module-card" style={{ '--accent': module.color, '--dim': module.dimColor, '--glow': module.glowColor }}>
      <div className="module-card-top">
        <div className="module-icon" style={{ color: module.color }}>
          {module.icon}
        </div>
        <span className="module-badge" style={{ color: module.color, background: module.dimColor, borderColor: `${module.color}30` }}>
          {module.badge}
        </span>
      </div>
      <h3 className="module-name">{module.name}</h3>
      <p className="module-desc">{module.description}</p>
      <ul className="module-caps">
        {module.capabilities.map(cap => (
          <li key={cap}>
            <span className="cap-bullet" style={{ color: module.color }}>›</span>
            {cap}
          </li>
        ))}
      </ul>
      <div className="module-deps">
        {module.deps.map(dep => (
          <span key={dep} className="dep-pill">{dep}</span>
        ))}
      </div>
    </div>
  )
}

function CodeBlock({ title, code }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="code-block">
      <div className="code-block-header">
        <span className="code-block-title">{title}</span>
        <button className="copy-btn" onClick={copy}>
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>
      <pre className="code-content">{code}</pre>
    </div>
  )
}

// ─── Page ───────────────────────────────────────────────────────────────────────

export default function Home() {
  const [visibleLines, setVisibleLines] = useState([])

  useEffect(() => {
    let index = 0
    const timeouts = []

    const addLine = () => {
      if (index >= TERMINAL_LINES.length) {
        const t = setTimeout(() => {
          setVisibleLines([])
          index = 0
          addLine()
        }, 4000)
        timeouts.push(t)
        return
      }
      setVisibleLines(prev => [...prev, TERMINAL_LINES[index]])
      index++
      const delay = TERMINAL_LINES[index - 1]?.type === 'blank' ? 80 : 150
      const t = setTimeout(addLine, delay)
      timeouts.push(t)
    }

    const initialDelay = setTimeout(addLine, 600)
    timeouts.push(initialDelay)

    return () => timeouts.forEach(clearTimeout)
  }, [])

  return (
    <>
      <Head>
        <title>ITEK VAPT Tool — Automated Security Assessment Suite</title>
        <meta name="description" content="ITEK VAPT Tool — an automated Python-based penetration testing suite for reconnaissance, SQL injection, CVE scanning, TLS analysis, and POST request fuzzing." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta property="og:title" content="ITEK VAPT Tool" />
        <meta property="og:description" content="Automated penetration testing suite: Recon, SQLi, CVE/DAST, POST Analysis, TLS Config." />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="app">

        {/* ── Nav ── */}
        <nav className="nav">
          <div className="nav-logo">
            <div className="logo-mark">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
                <line x1="12" y1="2" x2="12" y2="22"/>
                <path d="M2 8.5l10 6 10-6"/>
              </svg>
            </div>
            <span className="logo-name">ITEK</span>
            <span className="logo-sub">VAPT</span>
          </div>
          <div className="nav-actions">
            <a
              href="https://github.com/Z-40/ITEK_VAPT_TOOL"
              target="_blank"
              rel="noopener noreferrer"
              className="nav-gh-link"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
              </svg>
              GitHub
            </a>
          </div>
        </nav>

        {/* ── Hero ── */}
        <section className="hero">
          <div className="hero-eyebrow">
            <span className="eyebrow-dot" />
            AUTOMATED SECURITY ASSESSMENT SUITE
          </div>
          <h1 className="hero-title">
            <span className="glitch" data-text="ITEK">ITEK</span>
            {' '}
            <span className="hero-title-accent">VAPT</span>
          </h1>
          <p className="hero-subtitle">Tool</p>
          <p className="hero-desc">
            A modular Python penetration testing framework for comprehensive
            vulnerability discovery — recon, injection, CVE scanning, TLS
            analysis, and POST fuzzing in a single suite.
          </p>
          <div className="hero-ctas">
            <a
              href="https://github.com/Z-40/ITEK_VAPT_TOOL"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary"
            >
              View on GitHub
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="7" y1="17" x2="17" y2="7"/>
                <polyline points="7 7 17 7 17 17"/>
              </svg>
            </a>
            <a href="#modules" className="btn-secondary">
              Explore Modules
            </a>
          </div>
        </section>

        {/* ── Terminal ── */}
        <div className="terminal-wrapper">
          <Terminal lines={visibleLines} />
        </div>

        {/* ── Stats ── */}
        <div className="stats-bar">
          {STATS.map(stat => (
            <div key={stat.label} className="stat-item">
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* ── Modules ── */}
        <section id="modules" className="section">
          <div className="section-header">
            <span className="section-eyebrow">// ATTACK SURFACE</span>
            <h2 className="section-title">Security Modules</h2>
            <p className="section-desc">
              Five purpose-built modules covering every phase of a VAPT engagement.
            </p>
          </div>
          <div className="modules-grid">
            {MODULES.map(mod => (
              <ModuleCard key={mod.id} module={mod} />
            ))}
          </div>
        </section>

        {/* ── Stack ── */}
        <section className="section">
          <div className="section-header">
            <span className="section-eyebrow">// DEPENDENCIES</span>
            <h2 className="section-title">Technology Stack</h2>
            <p className="section-desc">
              35+ battle-tested Python libraries powering the tool.
            </p>
          </div>
          <div className="stack-grid">
            {STACK_GROUPS.map(group => (
              <div key={group.label} className="stack-group">
                <div className="stack-group-header">
                  <span className="stack-group-dot" style={{ background: group.color }} />
                  <span className="stack-group-label" style={{ color: group.color }}>{group.label}</span>
                </div>
                <div className="stack-pills">
                  {group.items.map(item => (
                    <span key={item} className="stack-pill" style={{ borderColor: `${group.color}25`, color: '#A0BCCC' }}>
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Quick Start ── */}
        <section className="section" id="quickstart">
          <div className="section-header">
            <span className="section-eyebrow">// GETTING STARTED</span>
            <h2 className="section-title">Quick Start</h2>
            <p className="section-desc">
              Clone, install dependencies, and launch your first scan in minutes.
            </p>
          </div>
          <div className="code-blocks-grid">
            <CodeBlock title="Installation" code={INSTALL_CODE} />
            <CodeBlock title="Run a Scan" code={SCAN_CODE} />
          </div>
        </section>

        {/* ── Footer ── */}
        <footer className="footer">
          <div className="footer-inner">
            <div className="footer-logo">
              <div className="logo-mark small">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
                </svg>
              </div>
              <span>ITEK VAPT Tool</span>
            </div>
            <div className="footer-links">
              <a href="https://github.com/Z-40/ITEK_VAPT_TOOL" target="_blank" rel="noopener noreferrer">
                GitHub Repository
              </a>
              <a href="https://github.com/Z-40/ITEK_VAPT_TOOL/blob/main/requirements.txt" target="_blank" rel="noopener noreferrer">
                Requirements
              </a>
              <a href="#modules">Modules</a>
              <a href="#quickstart">Quick Start</a>
            </div>
            <div className="footer-disclaimer">
              ⚠ For authorized security testing only. Unauthorized use against systems you do not own is illegal.
            </div>
            <div className="footer-copy">
              Built with Python · Open Source · github.com/Z-40/ITEK_VAPT_TOOL
            </div>
          </div>
        </footer>

      </div>

      <style jsx global>{`
        /* ─── Layout ─── */
        .app {
          position: relative;
          z-index: 1;
          max-width: 1200px;
          margin: 0 auto;
          padding: 0 24px;
        }

        /* ─── Nav ─── */
        .nav {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 24px 0 20px;
          border-bottom: 1px solid var(--border-dim);
          margin-bottom: 80px;
        }
        .nav-logo {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .logo-mark {
          width: 36px;
          height: 36px;
          background: var(--cyan-dim);
          border: 1px solid var(--border);
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: var(--cyan);
        }
        .logo-mark.small {
          width: 26px;
          height: 26px;
          border-radius: 5px;
        }
        .logo-name {
          font-family: 'JetBrains Mono', monospace;
          font-weight: 700;
          font-size: 18px;
          letter-spacing: 0.08em;
          color: var(--text);
        }
        .logo-sub {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          font-weight: 500;
          letter-spacing: 0.12em;
          color: var(--cyan);
          background: var(--cyan-dim);
          border: 1px solid var(--border);
          padding: 2px 7px;
          border-radius: 4px;
        }
        .nav-gh-link {
          display: flex;
          align-items: center;
          gap: 7px;
          color: var(--text-muted);
          font-size: 13px;
          font-weight: 500;
          transition: color 0.2s;
        }
        .nav-gh-link:hover { color: var(--cyan); }

        /* ─── Hero ─── */
        .hero {
          text-align: center;
          margin-bottom: 56px;
        }
        .hero-eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.18em;
          color: var(--text-muted);
          margin-bottom: 28px;
        }
        .eyebrow-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--cyan);
          display: inline-block;
          animation: pulse-ring 2s ease-out infinite;
          box-shadow: 0 0 0 0 var(--cyan-glow);
        }
        .hero-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: clamp(52px, 10vw, 96px);
          font-weight: 700;
          line-height: 0.95;
          letter-spacing: -0.02em;
          color: var(--text);
          margin-bottom: 4px;
        }
        .hero-title-accent {
          color: var(--cyan);
          text-shadow: 0 0 40px rgba(0, 229, 212, 0.4);
        }
        .hero-subtitle {
          font-family: 'JetBrains Mono', monospace;
          font-size: clamp(24px, 4vw, 40px);
          font-weight: 300;
          color: var(--text-muted);
          letter-spacing: 0.25em;
          text-transform: uppercase;
          margin-bottom: 28px;
        }
        .hero-desc {
          max-width: 560px;
          margin: 0 auto 36px;
          font-size: 16px;
          line-height: 1.7;
          color: var(--text-muted);
        }
        .hero-ctas {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 14px;
          flex-wrap: wrap;
        }
        .btn-primary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: var(--cyan);
          color: #04080F;
          font-weight: 600;
          font-size: 14px;
          border-radius: var(--radius);
          transition: all 0.2s;
          letter-spacing: 0.02em;
        }
        .btn-primary:hover {
          background: #33ECE2;
          transform: translateY(-1px);
          box-shadow: 0 8px 24px var(--cyan-glow);
        }
        .btn-secondary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: transparent;
          color: var(--text);
          font-weight: 500;
          font-size: 14px;
          border-radius: var(--radius);
          border: 1px solid var(--border);
          transition: all 0.2s;
        }
        .btn-secondary:hover {
          border-color: var(--cyan);
          color: var(--cyan);
          background: var(--cyan-dim);
        }

        /* ─── Glitch effect ─── */
        .glitch {
          position: relative;
          display: inline-block;
        }
        .glitch::before,
        .glitch::after {
          content: attr(data-text);
          position: absolute;
          top: 0; left: 0;
          width: 100%;
          color: var(--text);
        }
        .glitch::before {
          animation: glitch-1 6s infinite steps(1);
          color: var(--cyan);
          opacity: 0.7;
        }
        .glitch::after {
          animation: glitch-2 6s infinite steps(1);
          opacity: 0.5;
        }

        /* ─── Terminal ─── */
        .terminal-wrapper {
          margin: 0 auto 64px;
          max-width: 820px;
        }
        .terminal {
          background: #060d18;
          border: 1px solid rgba(0, 229, 212, 0.15);
          border-radius: var(--radius-lg);
          overflow: hidden;
          box-shadow:
            0 0 0 1px rgba(0, 229, 212, 0.05),
            0 24px 60px rgba(0, 0, 0, 0.6),
            0 0 80px rgba(0, 229, 212, 0.06);
          position: relative;
        }
        .terminal::after {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 2px;
          background: linear-gradient(90deg, transparent, var(--cyan), var(--purple), transparent);
          opacity: 0.6;
        }
        .terminal-header {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: rgba(0, 0, 0, 0.3);
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .terminal-dots {
          display: flex;
          gap: 6px;
        }
        .dot {
          width: 12px;
          height: 12px;
          border-radius: 50%;
        }
        .dot-red    { background: #FF5F57; }
        .dot-yellow { background: #FFBD2E; }
        .dot-green  { background: #28CA41; }
        .terminal-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: var(--text-dim);
          margin-left: auto;
          margin-right: auto;
          padding-right: 52px;
        }
        .terminal-body {
          padding: 20px 22px 20px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          line-height: 1.75;
          min-height: 300px;
          max-height: 420px;
          overflow-y: auto;
        }
        .terminal-line {
          display: block;
          white-space: pre;
          animation: terminal-line-in 0.12s ease-out forwards;
        }
        .cursor {
          display: inline-block;
          color: var(--cyan);
          animation: cursor-blink 1s infinite;
          font-family: 'JetBrains Mono', monospace;
          font-size: 14px;
        }

        /* ─── Stats ─── */
        .stats-bar {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 1px;
          background: var(--border-dim);
          border: 1px solid var(--border-dim);
          border-radius: var(--radius-lg);
          overflow: hidden;
          margin-bottom: 96px;
        }
        .stat-item {
          background: var(--surface);
          padding: 28px 24px;
          text-align: center;
          transition: background 0.2s;
        }
        .stat-item:hover { background: var(--surface-2); }
        .stat-value {
          font-family: 'JetBrains Mono', monospace;
          font-size: 36px;
          font-weight: 700;
          color: var(--cyan);
          line-height: 1;
          margin-bottom: 8px;
        }
        .stat-label {
          font-size: 12px;
          color: var(--text-muted);
          letter-spacing: 0.06em;
          text-transform: uppercase;
        }

        /* ─── Sections ─── */
        .section {
          margin-bottom: 96px;
        }
        .section-header {
          text-align: center;
          margin-bottom: 52px;
        }
        .section-eyebrow {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.18em;
          color: var(--cyan);
          display: block;
          margin-bottom: 12px;
        }
        .section-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: clamp(26px, 4vw, 38px);
          font-weight: 700;
          color: var(--text);
          margin-bottom: 14px;
          letter-spacing: -0.02em;
        }
        .section-desc {
          font-size: 15px;
          color: var(--text-muted);
          max-width: 480px;
          margin: 0 auto;
        }

        /* ─── Module Cards ─── */
        .modules-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
        }
        .modules-grid > *:nth-child(4),
        .modules-grid > *:nth-child(5) {
          grid-column: span 1;
        }

        /* 5 cards: 3 on top row, 2 centered on bottom */
        @media (min-width: 900px) {
          .modules-grid {
            grid-template-columns: repeat(6, 1fr);
          }
          .modules-grid > * {
            grid-column: span 2;
          }
          .modules-grid > *:nth-child(4) {
            grid-column: 2 / span 2;
          }
          .modules-grid > *:nth-child(5) {
            grid-column: 4 / span 2;
          }
        }

        .module-card {
          background: var(--surface);
          border: 1px solid var(--border-dim);
          border-radius: var(--radius-lg);
          padding: 24px;
          transition: all 0.25s ease;
          position: relative;
          overflow: hidden;
          border-left: 3px solid var(--accent);
        }
        .module-card::before {
          content: '';
          position: absolute;
          inset: 0;
          background: var(--glow);
          opacity: 0;
          transition: opacity 0.25s;
          pointer-events: none;
        }
        .module-card:hover {
          border-color: var(--accent);
          transform: translateY(-3px);
          box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4), 0 0 0 1px var(--accent, transparent)22;
        }
        .module-card:hover::before { opacity: 0.04; }
        .module-card-top {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          margin-bottom: 14px;
        }
        .module-icon {
          width: 44px;
          height: 44px;
          background: var(--dim);
          border-radius: var(--radius);
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }
        .module-badge {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.1em;
          padding: 3px 8px;
          border-radius: 4px;
          border: 1px solid;
        }
        .module-name {
          font-family: 'JetBrains Mono', monospace;
          font-size: 18px;
          font-weight: 700;
          color: var(--text);
          margin-bottom: 10px;
          letter-spacing: -0.01em;
        }
        .module-desc {
          font-size: 13px;
          color: var(--text-muted);
          line-height: 1.65;
          margin-bottom: 18px;
        }
        .module-caps {
          list-style: none;
          margin-bottom: 20px;
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .module-caps li {
          font-size: 12.5px;
          color: #8CA3BE;
          display: flex;
          align-items: flex-start;
          gap: 6px;
          line-height: 1.4;
        }
        .cap-bullet {
          font-weight: 700;
          flex-shrink: 0;
          margin-top: 1px;
        }
        .module-deps {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }
        .dep-pill {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          color: var(--text-dim);
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.06);
          border-radius: 4px;
          padding: 2px 7px;
        }

        /* ─── Stack ─── */
        .stack-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }
        .stack-group {
          background: var(--surface);
          border: 1px solid var(--border-dim);
          border-radius: var(--radius-lg);
          padding: 20px;
        }
        .stack-group-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 14px;
        }
        .stack-group-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .stack-group-label {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.1em;
          text-transform: uppercase;
        }
        .stack-pills {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }
        .stack-pill {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          padding: 3px 8px;
          border-radius: 4px;
          border: 1px solid;
          background: rgba(255,255,255,0.02);
          transition: background 0.2s;
        }
        .stack-pill:hover {
          background: rgba(255,255,255,0.06);
        }

        /* ─── Code blocks ─── */
        .code-blocks-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 20px;
        }
        .code-block {
          background: #060d18;
          border: 1px solid var(--border-dim);
          border-radius: var(--radius-lg);
          overflow: hidden;
        }
        .code-block-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 12px 16px;
          border-bottom: 1px solid rgba(255,255,255,0.04);
          background: rgba(0,0,0,0.25);
        }
        .code-block-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: var(--text-muted);
        }
        .copy-btn {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--text-muted);
          background: transparent;
          border: 1px solid var(--border-dim);
          border-radius: 4px;
          padding: 3px 10px;
          cursor: pointer;
          transition: all 0.2s;
        }
        .copy-btn:hover {
          color: var(--cyan);
          border-color: var(--border);
        }
        .code-content {
          padding: 18px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          line-height: 1.75;
          color: #C8D8E8;
          white-space: pre-wrap;
          word-break: break-all;
        }

        /* ─── Footer ─── */
        .footer {
          border-top: 1px solid var(--border-dim);
          padding: 40px 0 48px;
          margin-top: 24px;
        }
        .footer-inner {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 20px;
          text-align: center;
        }
        .footer-logo {
          display: flex;
          align-items: center;
          gap: 8px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 14px;
          font-weight: 600;
          color: var(--text);
        }
        .footer-links {
          display: flex;
          gap: 24px;
          flex-wrap: wrap;
          justify-content: center;
        }
        .footer-links a {
          font-size: 13px;
          color: var(--text-muted);
          transition: color 0.2s;
        }
        .footer-links a:hover { color: var(--cyan); }
        .footer-disclaimer {
          font-size: 12px;
          color: var(--amber);
          background: var(--amber-dim);
          border: 1px solid rgba(255, 184, 48, 0.2);
          border-radius: var(--radius);
          padding: 8px 16px;
        }
        .footer-copy {
          font-size: 12px;
          color: var(--text-dim);
          font-family: 'JetBrains Mono', monospace;
        }

        /* ─── Responsive ─── */
        @media (max-width: 900px) {
          .nav { margin-bottom: 48px; }
          .hero { margin-bottom: 40px; }
          .stats-bar { grid-template-columns: repeat(2, 1fr); margin-bottom: 64px; }
          .modules-grid { grid-template-columns: 1fr !important; }
          .modules-grid > * { grid-column: span 1 !important; }
          .stack-grid { grid-template-columns: repeat(2, 1fr); }
          .code-blocks-grid { grid-template-columns: 1fr; }
          .section { margin-bottom: 64px; }
        }

        @media (max-width: 600px) {
          .app { padding: 0 16px; }
          .hero-desc { font-size: 14px; }
          .stats-bar { grid-template-columns: repeat(2, 1fr); }
          .stat-value { font-size: 28px; }
          .stack-grid { grid-template-columns: 1fr; }
          .modules-grid { grid-template-columns: 1fr; }
          .hero-ctas { flex-direction: column; align-items: center; }
          .btn-primary, .btn-secondary { width: 100%; justify-content: center; }
        }
      `}</style>
    </>
  )
}
