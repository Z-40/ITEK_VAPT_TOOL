import React, { useState } from 'react';
import axios from 'axios';

interface CVEDASTPanelProps {
  apiBase: string;
  onResult: (data: any) => void;
}

const CVEDASTPanel: React.FC<CVEDASTPanelProps> = ({ apiBase, onResult }) => {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);

  const runScan = async () => {
    if (!target) {
      alert("Target is required");
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${apiBase}/api/cve-dast/detect`, null, {
        params: { target }
      });
      onResult({ tool: 'cve-dast', target, data: res.data });
    } catch (err: any) {
      alert(`CVE/DAST Error: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">🔍 CVE & DAST Scanner</h2>
      
      <div className="max-w-md space-y-6">
        <div>
          <label className="block text-sm mb-2 text-gray-400">TARGET URL / IP</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="cyber-input w-full text-lg"
            placeholder="https://example.com or 192.168.1.1"
          />
        </div>

        <button
          onClick={runScan}
          disabled={loading || !target}
          className="cyber-button w-full text-lg mt-4"
        >
          {loading ? "🔍 Scanning for CVEs..." : "Start CVE / DAST Scan"}
        </button>
      </div>
    </div>
  );
};

export default CVEDASTPanel;