import React, { useState } from 'react';
import axios from 'axios';

interface Props {
  apiBase: string;
  onResult: (data: any) => void;
}

const PostRequestsPanel: React.FC<Props> = ({ apiBase, onResult }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const runScan = async () => {
    if (!file) {
      alert("Please upload OpenAPI JSON file");
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);
    if (targetUrl) formData.append('target_url', targetUrl);

    try {
      const res = await axios.post(`${apiBase}/api/post-requests/scan`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      onResult({ tool: 'post-requests', data: res.data });
    } catch (err: any) {
      alert("Upload failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">📬 Post Requests Scanner</h2>
      
      <div className="max-w-lg space-y-6">
        <div>
          <label className="block text-sm mb-3 text-gray-400">Upload OpenAPI JSON File</label>
          <input
            type="file"
            accept=".json"
            onChange={handleFileChange}
            className="block w-full text-sm text-gray-400 file:mr-4 file:py-3 file:px-6 file:rounded-xl file:border-0 file:bg-cyan-500 file:text-black file:font-bold hover:file:bg-cyan-400"
          />
        </div>

        <div>
          <label className="block text-sm mb-2 text-gray-400">Target Base URL (optional)</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="cyber-input w-full"
            placeholder="https://target.com"
          />
        </div>

        <button
          onClick={runScan}
          disabled={loading || !file}
          className="cyber-button w-full text-lg"
        >
          {loading ? "Uploading & Scanning..." : "🚀 Start Scan"}
        </button>
      </div>
    </div>
  );
};

export default PostRequestsPanel;