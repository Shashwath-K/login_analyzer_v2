import { Upload, Database, Activity, Target, Shield, Clock } from 'lucide-react'

export default function UploadPanel({ onFile, onSample, onSimulate, loading }) {
  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (file) onFile(file)
  }

  const simulations = [
    { type: 'brute_force', label: 'Brute Force', icon: <Target size={14} color="#ef4444" /> },
    { type: 'credential_stuffing', label: 'Credential Stuffing', icon: <Database size={14} color="#f97316" /> },
    { type: 'dictionary', label: 'Dictionary', icon: <Activity size={14} color="#8b5cf6" /> },
    { type: 'normal', label: 'Normal Traffic', icon: <Shield size={14} color="#22c55e" /> }
  ]

  return (
    <div className="card">
      <div className="card-header">
        <Upload size={16} color="#38bdf8" />
        <span className="card-title">Data Ingestion</span>
      </div>
      <div className="card-body">
        {/* Dropzone mockup using standard input */}
        <label className={`dropzone${loading ? ' active' : ''}`} style={{ marginBottom: 20 }}>
          <input type="file" onChange={handleFileChange} accept=".csv" disabled={loading} style={{ display: 'none' }} />
          <Upload className="dropzone-icon" size={32} />
          <div className="dropzone-title">Click to upload login logs (CSV)</div>
          <div className="dropzone-sub">Files should contain: timestamp, ip_address, username, status and password_used.</div>
        </label>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 20 }}>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          <span style={{ fontSize: 11, color: 'var(--mu)', fontWeight: 700, textTransform: 'uppercase' }}>or</span>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>

        <button 
          className="btn btn-secondary w-full" 
          onClick={onSample}
          disabled={loading}
          style={{ marginBottom: 24 }}
        >
          <Database size={16} />
          <span>Load System Sample Logs</span>
        </button>

        <div style={{ marginTop: 24 }}>
          <div className="card-title" style={{ marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
            <Clock size={14} color="var(--mu)" />
            <span>Attack Simulators</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {simulations.map(s => (
              <button 
                key={s.type}
                className="btn btn-secondary" 
                onClick={() => onSimulate(s.type, 20)}
                disabled={loading}
                style={{ fontSize: 11, justifyContent: 'flex-start', padding: '10px' }}
              >
                {s.icon}
                <span style={{ marginLeft: 4 }}>{s.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
