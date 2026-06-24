import React from 'react';

interface ResultsViewerProps {
  data: any;
}

const ResultsViewer: React.FC<ResultsViewerProps> = ({ data }) => {
  if (!data) return null;

  return (
    <div className="mt-12 bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-2xl font-bold text-cyan-400">📊 SCAN RESULTS</h3>
        <div className="text-sm text-gray-500">
          {new Date(data.timestamp || Date.now()).toLocaleString()}
        </div>
      </div>

      <pre className="bg-black/70 p-6 rounded-2xl border border-gray-700 overflow-auto max-h-[70vh] text-sm text-gray-300 whitespace-pre-wrap">
        {JSON.stringify(data, null, 2)}
      </pre>

      <div className="mt-6 text-xs text-gray-500 text-center">
        Results saved to <span className="text-cyan-400">outputs/</span> folder on backend
      </div>
    </div>
  );
};

export default ResultsViewer;