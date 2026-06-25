import React from 'react';

interface Props {
  data: any;
}

const ResultsViewer: React.FC<Props> = ({ data }) => {
  if (!data) return null;

  const { tool, target, data: scanData } = data;

  return (
    <div className="mt-12 bg-zinc-950 border border-cyan-500/30 rounded-3xl p-8">
      <div className="flex justify-between items-center mb-8">
        <h3 className="text-2xl font-bold text-cyan-400">📊 SCAN RESULTS — {tool.toUpperCase()}</h3>
        <span className="text-sm text-gray-500">{new Date().toLocaleString()}</span>
      </div>

      {scanData?.open_ports && (
        <div className="mb-8">
          <h4 className="text-lg mb-4 text-cyan-300">Open Ports</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {scanData.open_ports.map((port: any, i: number) => (
              <div key={i} className="bg-black/60 border border-green-500/30 rounded-xl p-4 text-center">
                <div className="text-green-400 text-xl font-bold">Port {port.port}</div>
                <div className="text-sm text-gray-400">{port.service || 'Unknown'}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* General Results Display */}
      <pre className="bg-black/70 p-6 rounded-2xl border border-gray-700 text-sm overflow-auto max-h-[60vh] text-gray-300">
        {JSON.stringify(scanData, null, 2)}
      </pre>
    </div>
  );
};

export default ResultsViewer;