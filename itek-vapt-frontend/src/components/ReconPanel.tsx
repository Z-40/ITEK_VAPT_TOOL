import React, { useState } from 'react';
import axios from 'axios';

interface ReconPanelProps {
  apiBase: string;
  onResult: (data: any) => void;
}

const ReconPanel: React.FC<ReconPanelProps> = ({ apiBase, onResult }) => {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTool, setActiveTool] = useState('');

  const runScan = async (tool: string) => {
    if (!target) {
      alert("Please enter a target");
      return;
    }

    setLoading(true);
    setActiveTool(tool);

    try {
      const payload = { 
        target, 
        ports: ports ? ports.split(',').map(p => parseInt(p.trim())) : null 
      };

      const res = await axios.post(`${apiBase}/api/recon/${tool}`, payload);
      onResult({ tool, target, timestamp: new Date(), data: res.data });
    } catch (err: any) {
      alert(`Error running ${tool}: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const tools = [
    { id: 'port-scan', label: 'Port Scan', icon: '🔍' },
    { id: 'dns-scan', label: 'DNS Enum', icon: '🌐' },
    { id: 'fingerprint', label: 'Fingerprint', icon: '🔬' },
    { id: 'tls-scan', label: 'TLS Scan', icon: '🔒' },
    { id: 'web-path', label: 'Web Paths', icon: '🕸️' },
    { id: 'rdap', label: 'RDAP', icon: '📋' },
    { id: 'enumerate', label: 'Full Enum', icon: '⚡' },
    { id: 'aggregate', label: 'Aggregate All', icon: '📊' },
  ];

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">🛡️ Reconnaissance Suite</h2>
      
      <div className="space-y-6">
        <div>
          <label className="block text-sm mb-2 text-gray-400">TARGET</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="cyber-input w-full text-lg"
            placeholder="example.com or 192.168.1.0/24"
          />
        </div>

        <div>
          <label className="block text-sm mb-2 text-gray-400">PORTS (optional, comma separated)</label>
          <input
            type="text"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            className="cyber-input w-full"
            placeholder="80,443,8080"
          />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6">
          {tools.map(tool => (
            <button
              key={tool.id}
              onClick={() => runScan(tool.id)}
              disabled={loading}
              className="group bg-zinc-900 hover:bg-zinc-800 border border-cyan-500/30 hover:border-cyan-400 p-6 rounded-2xl transition-all flex flex-col items-center gap-3"
            >
              <span className="text-4xl group-hover:scale-110 transition-transform">{tool.icon}</span>
              <span className="font-medium text-sm">{tool.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ReconPanel;