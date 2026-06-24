import React, { useState } from 'react';
import axios from 'axios';

interface PostRequestsPanelProps {
  apiBase: string;
  onResult: (data: any) => void;
}

const PostRequestsPanel: React.FC<PostRequestsPanelProps> = ({ apiBase, onResult }) => {
  const [openapiPath, setOpenapiPath] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const runScan = async () => {
    if (!openapiPath) {
      alert("OpenAPI JSON path is required");
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${apiBase}/api/post-requests/scan`, {
        openapi_path: openapiPath,
        target_url: targetUrl || undefined
      });
      onResult({ tool: 'post-requests', data: res.data });
    } catch (err: any) {
      alert(`Post Requests Error: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-8">📬 Post Requests Scanner</h2>
      
      <div className="space-y-6 max-w-md">
        <div>
          <label className="block text-sm mb-2 text-gray-400">OpenAPI JSON Path</label>
          <input
            type="text"
            value={openapiPath}
            onChange={(e) => setOpenapiPath(e.target.value)}
            className="cyber-input w-full"
            placeholder="features/post_requests/openapi.json"
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
          disabled={loading || !openapiPath}
          className="cyber-button w-full text-lg mt-4"
        >
          {loading ? "Scanning..." : "Run Post Requests Scan"}
        </button>
      </div>
    </div>
  );
};

export default PostRequestsPanel;