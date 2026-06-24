import React, { useState } from 'react';
import axios from 'axios';

interface SQLiPanelProps {
  apiBase: string;
  onResult: (data: any) => void;
}

const SQLiPanel: React.FC<SQLiPanelProps> = ({ apiBase, onResult }) => {
  const [requestDir, setRequestDir] = useState('');
  const [workers, setWorkers] = useState(4);
  const [loading, setLoading] = useState(false);

  const runSQLi = async () => {
    if (!requestDir) {
      alert("Request directory path is required");
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${apiBase}/api/sqli/run`, {
        request_dir: requestDir,
        workers
      });
      onResult({ tool: 'sqli', directory: requestDir, data: res.data });
    } catch (err: any) {
      alert(`SQLi Error: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">💉 SQL Injection Scanner</h2>
      
      <div className="space-y-6 max-w-md">
        <div>
          <label className="block text-sm mb-2 text-gray-400">REQUEST DIRECTORY PATH</label>
          <input
            type="text"
            value={requestDir}
            onChange={(e) => setRequestDir(e.target.value)}
            className="cyber-input w-full"
            placeholder="/path/to/requests"
          />
        </div>

        <div>
          <label className="block text-sm mb-2 text-gray-400">WORKERS (Parallel)</label>
          <input
            type="number"
            value={workers}
            onChange={(e) => setWorkers(parseInt(e.target.value))}
            className="cyber-input w-full"
            min="1"
            max="20"
          />
        </div>

        <button
          onClick={runSQLi}
          disabled={loading || !requestDir}
          className="cyber-button w-full text-lg mt-4"
        >
          {loading ? "🚀 Running SQLMap..." : "Start SQL Injection Scan"}
        </button>
      </div>
    </div>
  );
};

export default SQLiPanel;