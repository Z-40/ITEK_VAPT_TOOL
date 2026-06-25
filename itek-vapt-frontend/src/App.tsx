import { useState } from 'react'
import { Tab } from '@headlessui/react'
import ReconPanel from './components/ReconPanel'
import SQLiPanel from './components/SQLiPanel'
import PostRequestsPanel from './components/PostRequestsPanel'
import CVEDASTPanel from './components/CVEDASTPanel'
import ResultsViewer from './components/ResultsViewer'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [results, setResults] = useState<any>(null)

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <header className="border-b border-cyan-500/20 bg-black/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-8 py-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="text-4xl font-bold tracking-tighter">
              <span className="text-cyan-400">ITEK</span> VAPT
            </div>
          </div>
          <div className="text-sm text-gray-500">Vulnerability Assessment Platform</div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-8 py-10">
        <Tab.Group>
          <Tab.List className="flex gap-2 border-b border-gray-800 mb-10">
            {['Recon', 'SQL Injection', 'Post Requests', 'CVE / DAST'].map((tab, i) => (
              <Tab key={i} className={({ selected }) => `px-8 py-4 text-sm font-medium rounded-t-xl transition-all ${selected ? 'bg-cyan-500 text-black' : 'text-gray-400 hover:text-white'}`}>
                {tab}
              </Tab>
            ))}
          </Tab.List>

          <Tab.Panels>
            <Tab.Panel><ReconPanel apiBase={API_BASE} onResult={setResults} /></Tab.Panel>
            <Tab.Panel><SQLiPanel apiBase={API_BASE} onResult={setResults} /></Tab.Panel>
            <Tab.Panel><PostRequestsPanel apiBase={API_BASE} onResult={setResults} /></Tab.Panel>
            <Tab.Panel><CVEDASTPanel apiBase={API_BASE} onResult={setResults} /></Tab.Panel>
          </Tab.Panels>
        </Tab.Group>

        {results && <ResultsViewer data={results} />}
      </div>
    </div>
  )
}

export default App