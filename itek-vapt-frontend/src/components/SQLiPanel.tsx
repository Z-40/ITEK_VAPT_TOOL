import React, { useState } from 'react';
import axios from 'axios';

interface Props {
  apiBase: string;
  onResult: (data: any) => void;
}

const SQLiPanel: React.FC<Props> = ({ apiBase, onResult }) => {
  const [files, setFiles] = useState<FileList | null>(null);
  const [workers, setWorkers] = useState(4);
  const [loading, setLoading] = useState(false);

  const handleFiles = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) setFiles(e.target.files);
  };

  const runSQLi = async () => {
    if (!files || files.length === 0) {
      alert("Please upload request files");
      return;
    }

    setLoading(true);
    const formData = new FormData();
    Array.from(files).forEach(file => formData.append('files', file));
    formData.append('workers', workers.toString());

    try {
      const res = await axios.post(`${apiBase}/api/sqli/run`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      onResult({ tool: 'sqli', data: res.data });
    } catch (err: any) {
      alert("SQLi Error: " + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">💉 SQL Injection Scanner</h2>
      
      <div className="max-w-lg space-y-6">
        <div>
          <label className="block text-sm mb-3 text-gray-400">Upload Request Files (Burp/ZAP exports)</label>
          <input
            type="file"
            multiple
            onChange={handleFiles}
            className="block w-full text-sm text-gray-400 file:mr-4 file:py-3 file:px-6 file:rounded-xl file:border-0 file:bg-cyan-500 file:text-black file:font-bold"
          />
          <p className="text-xs text-gray-500 mt-2">You can select multiple files</p>
        </div>

        <div>
          <label className="block text-sm mb-2 text-gray-400">Workers (Parallel Scans)</label>
          <input
            type="number"
            value={workers}
            onChange={(e) => setWorkers(parseInt(e.target.value))}
            min="1"
            max="20"
            className="cyber-input w-full"
          />
        </div>

        <button
          onClick={runSQLi}
          disabled={loading || !files}
          className="cyber-button w-full text-lg"
        >
          {loading ? "Scanning..." : "Start SQL Injection Scan"}
        </button>
      </div>
    </div>
  );
};

export default SQLiPanel;