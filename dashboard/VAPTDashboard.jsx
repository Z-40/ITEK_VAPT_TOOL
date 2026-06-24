import React, { useState, useCallback } from 'react';
import { AlertCircle, Shield, Target, Network, Zap, TrendingUp, Settings, ChevronDown, Plus, X, Play, BarChart3 } from 'lucide-react';

// ============================================================================
// MAIN DASHBOARD COMPONENT
// ============================================================================
const VAPTDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [scanRuns, setScanRuns] = useState([
    { id: 1, target: '192.168.1.100', type: 'Port Scan', status: 'completed', date: '2024-01-15', severity: 'high', vulnerabilities: 14 },
    { id: 2, target: 'example.com', type: 'Web Vulnerability', status: 'running', date: '2024-01-14', severity: 'medium', vulnerabilities: 5 },
  ]);
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [expandedDetails, setExpandedDetails] = useState(null);

  const totalVulnerabilities = scanRuns.reduce((sum, run) => sum + run.vulnerabilities, 0);
  const criticalCount = scanRuns.filter(r => r.severity === 'critical').length;
  const highCount = scanRuns.filter(r => r.severity === 'high').length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white font-sans">
      {/* Header */}
      <Header onNewScan={() => setShowNewScanModal(true)} />

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Grid */}
        <StatsGrid 
          totalVulnerabilities={totalVulnerabilities}
          criticalCount={criticalCount}
          highCount={highCount}
          scansCompleted={scanRuns.filter(r => r.status === 'completed').length}
          scanRunning={scanRuns.filter(r => r.status === 'running').length}
        />

        {/* Tabs */}
        <div className="mt-12">
          <TabMenu activeTab={activeTab} onTabChange={setActiveTab} />

          {/* Tab Content */}
          <div className="mt-6">
            {activeTab === 'overview' && (
              <OverviewTab scanRuns={scanRuns} expandedDetails={expandedDetails} setExpandedDetails={setExpandedDetails} />
            )}
            {activeTab === 'scans' && (
              <ScansTab scanRuns={scanRuns} expandedDetails={expandedDetails} setExpandedDetails={setExpandedDetails} />
            )}
            {activeTab === 'tools' && (
              <ToolsTab onNewScan={() => setShowNewScanModal(true)} />
            )}
            {activeTab === 'settings' && (
              <SettingsTab />
            )}
          </div>
        </div>
      </main>

      {/* Modals */}
      {showNewScanModal && (
        <NewScanModal 
          onClose={() => setShowNewScanModal(false)}
          onSubmit={(scanData) => {
            setScanRuns([...scanRuns, { ...scanData, id: Math.max(...scanRuns.map(r => r.id), 0) + 1, status: 'running', vulnerabilities: 0 }]);
            setShowNewScanModal(false);
          }}
        />
      )}
    </div>
  );
};

// ============================================================================
// HEADER COMPONENT
// ============================================================================
const Header = ({ onNewScan }) => (
  <header className="border-b border-slate-700 bg-slate-800/50 backdrop-blur-sm sticky top-0 z-30">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-500 rounded-lg flex items-center justify-center">
            <Shield size={24} className="text-slate-900" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">ITEK VAPT</h1>
            <p className="text-xs text-slate-400">Vulnerability Assessment & Penetration Testing</p>
          </div>
        </div>
        <button
          onClick={onNewScan}
          className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 px-4 py-2 rounded-lg font-medium transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/50"
        >
          <Plus size={18} />
          New Scan
        </button>
      </div>
    </div>
  </header>
);

// ============================================================================
// STATS GRID
// ============================================================================
const StatsGrid = ({ totalVulnerabilities, criticalCount, highCount, scansCompleted, scanRunning }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <StatCard
      icon={AlertCircle}
      label="Total Vulnerabilities"
      value={totalVulnerabilities}
      color="from-red-600 to-red-500"
      subtitle={`${criticalCount} critical, ${highCount} high`}
    />
    <StatCard
      icon={Shield}
      label="Scans Completed"
      value={scansCompleted}
      color="from-green-600 to-green-500"
    />
    <StatCard
      icon={Zap}
      label="Active Scans"
      value={scanRunning}
      color="from-amber-600 to-amber-500"
    />
    <StatCard
      icon={TrendingUp}
      label="Risk Score"
      value="7.2/10"
      color="from-orange-600 to-orange-500"
      subtitle="High risk"
    />
  </div>
);

const StatCard = ({ icon: Icon, label, value, color, subtitle }) => (
  <div className={`bg-gradient-to-br ${color} p-0.5 rounded-lg`}>
    <div className="bg-slate-800 rounded-lg p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-sm font-medium">{label}</p>
          <p className="text-4xl font-bold mt-2">{value}</p>
          {subtitle && <p className="text-xs text-slate-400 mt-2">{subtitle}</p>}
        </div>
        <Icon size={28} className={`text-gradient-to-r ${color}`} style={{
          background: `linear-gradient(135deg, ${color.includes('red') ? 'rgb(220, 38, 38)' : color.includes('green') ? 'rgb(34, 197, 94)' : color.includes('amber') ? 'rgb(217, 119, 6)' : 'rgb(234, 88, 12)'})`,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }} />
      </div>
    </div>
  </div>
);

// ============================================================================
// TAB MENU
// ============================================================================
const TabMenu = ({ activeTab, onTabChange }) => {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'scans', label: 'Scan History' },
    { id: 'tools', label: 'Tools' },
    { id: 'settings', label: 'Settings' },
  ];

  return (
    <div className="flex border-b border-slate-700">
      {tabs.map(tab => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          className={`px-4 py-3 font-medium text-sm transition-all duration-300 border-b-2 -mb-px ${
            activeTab === tab.id
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
};

// ============================================================================
// TABS
// ============================================================================
const OverviewTab = ({ scanRuns, expandedDetails, setExpandedDetails }) => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Recent Scans */}
      <div className="lg:col-span-2">
        <h2 className="text-xl font-bold mb-4">Recent Scans</h2>
        <div className="space-y-3">
          {scanRuns.slice(0, 3).map(scan => (
            <ScanResultCard
              key={scan.id}
              scan={scan}
              isExpanded={expandedDetails === scan.id}
              onToggle={() => setExpandedDetails(expandedDetails === scan.id ? null : scan.id)}
            />
          ))}
        </div>
      </div>

      {/* Vulnerability Distribution */}
      <div>
        <h2 className="text-xl font-bold mb-4">Severity Distribution</h2>
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <div className="space-y-4">
            <VulnerabilityBar label="Critical" count={2} total={20} color="from-red-600 to-red-500" />
            <VulnerabilityBar label="High" count={5} total={20} color="from-orange-600 to-orange-500" />
            <VulnerabilityBar label="Medium" count={8} total={20} color="from-amber-600 to-amber-500" />
            <VulnerabilityBar label="Low" count={5} total={20} color="from-blue-600 to-blue-500" />
          </div>
        </div>
      </div>
    </div>
  </div>
);

const ScansTab = ({ scanRuns, expandedDetails, setExpandedDetails }) => (
  <div>
    <h2 className="text-xl font-bold mb-4">All Scan Results</h2>
    <div className="space-y-3">
      {scanRuns.map(scan => (
        <ScanResultCard
          key={scan.id}
          scan={scan}
          isExpanded={expandedDetails === scan.id}
          onToggle={() => setExpandedDetails(expandedDetails === scan.id ? null : scan.id)}
        />
      ))}
    </div>
  </div>
);

const ToolsTab = ({ onNewScan }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    {[
      { icon: Network, name: 'Port Scan', description: 'Scan open ports and services', color: 'from-blue-600 to-blue-500' },
      { icon: Target, name: 'Web Vulnerability', description: 'Detect web application vulnerabilities', color: 'from-purple-600 to-purple-500' },
      { icon: Zap, name: 'DNS Enumeration', description: 'Enumerate DNS records and subdomains', color: 'from-cyan-600 to-cyan-500' },
      { icon: Shield, name: 'SSL/TLS Config', description: 'Analyze SSL/TLS certificate and config', color: 'from-green-600 to-green-500' },
      { icon: AlertCircle, name: 'CVE Checker', description: 'Check for known CVE vulnerabilities', color: 'from-red-600 to-red-500' },
      { icon: TrendingUp, name: 'Fingerprinting', description: 'Identify running services and versions', color: 'from-amber-600 to-amber-500' },
    ].map((tool, idx) => (
      <ToolCard key={idx} tool={tool} onSelect={onNewScan} />
    ))}
  </div>
);

const SettingsTab = () => (
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <SettingsSection title="Scan Configuration">
      <SettingItem label="Default Timeout" value="300 seconds" editable />
      <SettingItem label="Threads" value="10" editable />
      <SettingItem label="User Agent" value="Mozilla/5.0..." editable />
    </SettingsSection>

    <SettingsSection title="Notifications">
      <SettingToggle label="Email on completion" defaultValue={true} />
      <SettingToggle label="Alert on critical findings" defaultValue={true} />
      <SettingToggle label="Daily summary report" defaultValue={false} />
    </SettingsSection>

    <SettingsSection title="API Keys">
      <SettingItem label="CVE Database API" value="••••••••" editable masked />
    </SettingsSection>

    <SettingsSection title="Export Settings">
      <div className="space-y-2">
        <button className="w-full bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-lg transition-colors duration-300">
          Export Scans (JSON)
        </button>
        <button className="w-full bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-lg transition-colors duration-300">
          Export Reports (PDF)
        </button>
      </div>
    </SettingsSection>
  </div>
);

// ============================================================================
// COMPONENT PARTS
// ============================================================================
const ScanResultCard = ({ scan, isExpanded, onToggle }) => (
  <div className="bg-slate-800 border border-slate-700 hover:border-slate-600 rounded-lg transition-all duration-300">
    <button
      onClick={onToggle}
      className="w-full text-left p-4 hover:bg-slate-700/50 transition-colors duration-200"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4 flex-1">
          <div className={`w-3 h-3 rounded-full ${scan.status === 'running' ? 'bg-amber-500 animate-pulse' : 'bg-green-500'}`} />
          <div className="flex-1">
            <h3 className="font-semibold text-white">{scan.target}</h3>
            <p className="text-xs text-slate-400">{scan.type} • {scan.date}</p>
          </div>
          <div className="flex items-center gap-3">
            <SeverityBadge severity={scan.severity} />
            <span className="text-sm font-medium text-slate-300">{scan.vulnerabilities} vulnerabilities</span>
            <ChevronDown size={18} className={`transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`} />
          </div>
        </div>
      </div>
    </button>

    {isExpanded && (
      <div className="border-t border-slate-700 p-4 bg-slate-700/30">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <DetailItem label="Target" value={scan.target} />
          <DetailItem label="Type" value={scan.type} />
          <DetailItem label="Status" value={scan.status} />
          <DetailItem label="Date" value={scan.date} />
          <DetailItem label="Vulnerabilities" value={scan.vulnerabilities} />
          <DetailItem label="Severity" value={scan.severity} />
        </div>
        <div className="mt-4 pt-4 border-t border-slate-700 flex gap-2">
          <button className="flex-1 bg-slate-600 hover:bg-slate-500 py-2 rounded transition-colors duration-300 text-xs font-medium">
            View Details
          </button>
          <button className="flex-1 bg-cyan-500 hover:bg-cyan-400 py-2 rounded transition-colors duration-300 text-xs font-medium text-slate-900">
            Export Report
          </button>
        </div>
      </div>
    )}
  </div>
);

const ToolCard = ({ tool, onSelect }) => {
  const Tool = tool.icon;
  return (
    <div className={`bg-gradient-to-br ${tool.color} p-0.5 rounded-lg cursor-pointer hover:shadow-lg transition-all duration-300`}>
      <div className="bg-slate-800 rounded-lg p-6 h-full flex flex-col">
        <Tool size={32} className="mb-4 text-cyan-400" />
        <h3 className="font-bold text-lg mb-2">{tool.name}</h3>
        <p className="text-sm text-slate-400 flex-1 mb-4">{tool.description}</p>
        <button
          onClick={onSelect}
          className="w-full bg-slate-700 hover:bg-slate-600 py-2 rounded transition-colors duration-300 text-sm font-medium flex items-center justify-center gap-2"
        >
          <Play size={14} />
          Run Now
        </button>
      </div>
    </div>
  );
};

const VulnerabilityBar = ({ label, count, total, color }) => (
  <div>
    <div className="flex justify-between mb-1">
      <span className="text-sm font-medium">{label}</span>
      <span className="text-sm text-slate-400">{count}/{total}</span>
    </div>
    <div className="w-full bg-slate-700 rounded-full h-2">
      <div
        className={`bg-gradient-to-r ${color} h-2 rounded-full transition-all duration-500`}
        style={{ width: `${(count / total) * 100}%` }}
      />
    </div>
  </div>
);

const SeverityBadge = ({ severity }) => {
  const colors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium border ${colors[severity] || colors.low}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
};

const DetailItem = ({ label, value }) => (
  <div>
    <p className="text-slate-400">{label}</p>
    <p className="font-medium">{value}</p>
  </div>
);

const SettingsSection = ({ title, children }) => (
  <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
    <h3 className="font-bold text-lg mb-4">{title}</h3>
    <div className="space-y-3">{children}</div>
  </div>
);

const SettingItem = ({ label, value, editable, masked }) => (
  <div className="flex items-center justify-between py-2">
    <span className="text-sm text-slate-300">{label}</span>
    {editable ? (
      <input
        type={masked ? 'password' : 'text'}
        defaultValue={value}
        className="bg-slate-700 border border-slate-600 px-3 py-1 rounded text-sm w-40"
      />
    ) : (
      <span className="text-sm text-slate-400">{value}</span>
    )}
  </div>
);

const SettingToggle = ({ label, defaultValue }) => (
  <div className="flex items-center justify-between py-2">
    <span className="text-sm text-slate-300">{label}</span>
    <input
      type="checkbox"
      defaultChecked={defaultValue}
      className="w-4 h-4 rounded cursor-pointer"
    />
  </div>
);

// ============================================================================
// NEW SCAN MODAL
// ============================================================================
const NewScanModal = ({ onClose, onSubmit }) => {
  const [formData, setFormData] = useState({
    target: '',
    type: 'Port Scan',
    date: new Date().toISOString().split('T')[0],
  });

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 border border-slate-700 rounded-lg max-w-md w-full">
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <h2 className="text-xl font-bold">Create New Scan</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors duration-300"
          >
            <X size={24} />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Target</label>
            <input
              type="text"
              placeholder="192.168.1.1 or example.com"
              className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              value={formData.target}
              onChange={(e) => setFormData({ ...formData, target: e.target.value })}
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Scan Type</label>
            <select
              className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
            >
              <option>Port Scan</option>
              <option>Web Vulnerability</option>
              <option>DNS Enumeration</option>
              <option>SSL/TLS Config</option>
              <option>CVE Checker</option>
              <option>Fingerprinting</option>
            </select>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              onClick={onClose}
              className="flex-1 bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded font-medium transition-colors duration-300"
            >
              Cancel
            </button>
            <button
              onClick={() => onSubmit(formData)}
              className="flex-1 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 px-4 py-2 rounded font-medium transition-all duration-300"
            >
              Start Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VAPTDashboard;
