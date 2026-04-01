import { ShieldAlert, Search, Upload } from 'lucide-react'
import UploadPanel from '../components/UploadPanel.jsx'
import ClassificationTable from '../components/ClassificationTable.jsx'

export default function AnalysisPage({ data, loading, error, onFile, onSample, onSimulate }) {
  return (
    <div className="fade-up">
      <div className="flex items-center gap-4" style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em' }}>ML Analysis Pipeline</h1>
        <div style={{ padding: '4px 10px', background: 'rgba(56,189,248,0.1)', color: 'var(--a1)', borderRadius: 9999, fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>
           Intelligent Analysis Engine
        </div>
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: 'minmax(300px, 420px) 1fr', alignItems: 'start' }}>
        <div className="flex flex-col gap-4">
          <UploadPanel onFile={onFile} onSample={onSample} onSimulate={onSimulate} loading={loading} />
          
          {error && (
            <div className="card" style={{ borderLeft: '4px solid var(--a2)', background: 'rgba(239, 68, 68, 0.05)' }}>
              <div className="card-body flex items-center gap-4">
                <ShieldAlert size={24} color="var(--a2)" />
                <div>
                   <div style={{ fontWeight: 700, color: 'var(--a2)' }}>Analysis Error</div>
                   <div style={{ fontSize: 12, color: 'var(--mu)', marginTop: 2 }}>{error}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <Search size={16} color="var(--a1)" />
            <span className="card-title">Security Threat Classification Engine</span>
          </div>
          <div className="card-body">
            {loading ? (
              <div className="flex flex-col items-center justify-center" style={{ padding: '100px 20px', color: 'var(--mu)' }}>
                <div className="spinner" style={{ marginBottom: 20 }}></div>
                <div style={{ fontWeight: 600 }}>ML Inference in Progress...</div>
              </div>
            ) : error ? (
              <div className="flex flex-col items-center justify-center text-center" style={{ padding: '80px 20px' }}>
                 <ShieldAlert size={48} color="var(--a2)" style={{ marginBottom: 16, opacity: 0.3 }} />
                 <div style={{ fontWeight: 700, color: 'var(--a2)' }}>Analysis Failed</div>
                 <div style={{ fontSize: 13, color: 'var(--mu)', marginTop: 8, maxWidth: 300 }}>{error}</div>
              </div>
            ) : (
              <ClassificationTable data={data} />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
