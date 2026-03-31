import { useCallback, useState } from 'react'

export default function UploadPanel({ onFile, onSample, onSimulate, loading }) {
  const [dragging, setDragging] = useState(false)
  const [fileName, setFileName] = useState('')
  const [simType, setSimType]   = useState('brute_force')
  const [simCount, setSimCount] = useState(20)

  const handleFile = useCallback((file) => {
    if (!file || !file.name.endsWith('.csv')) return
    setFileName(file.name)
    onFile(file)
  }, [onFile])

  const onDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    handleFile(file)
  }, [handleFile])

  const onInputChange = useCallback((e) => {
    handleFile(e.target.files[0])
  }, [handleFile])

  return (
    <div className="card fade-up">
      <div className="card-header">
        <span>📂</span>
        <span className="card-title" style={{ color: 'var(--a1)' }}>Data Source</span>
      </div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>

          {/* Upload CSV */}
          <div>
            <div style={{ fontSize: 10, color: 'var(--mu)', letterSpacing: '.1em', marginBottom: 8 }}>
              UPLOAD LOGIN LOG CSV
            </div>
            <label>
              <div
                className={`dropzone${dragging ? ' active' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                style={{ cursor: 'pointer' }}
              >
                <div className="dropzone-icon">⬆️</div>
                <div className="dropzone-text">
                  <strong>Click or drag</strong> a CSV file
                </div>
                <div style={{ fontSize: 10, color: 'var(--mu)' }}>login_logs.csv format required</div>
                {fileName && <div className="file-name">✅ {fileName}</div>}
              </div>
              <input type="file" accept=".csv" onChange={onInputChange} style={{ display: 'none' }} />
            </label>
          </div>

          {/* Sample data */}
          <div>
            <div style={{ fontSize: 10, color: 'var(--mu)', letterSpacing: '.1em', marginBottom: 8 }}>
              USE BUILT-IN SAMPLE DATA
            </div>
            <div style={{
              border: '1px solid var(--border2)', borderRadius: 'var(--radius)',
              padding: 20, height: 'calc(100% - 22px)', display: 'flex',
              flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: 10,
            }}>
              <div style={{ fontSize: 28 }}>🗄️</div>
              <div style={{ fontSize: 11, color: 'var(--mu)', textAlign: 'center' }}>
                Analyze <strong style={{ color: 'var(--tx)' }}>login_logs.csv</strong><br />
                from the data directory
              </div>
              <button className="btn btn-outline" onClick={onSample} disabled={loading} style={{ width: '100%' }}>
                {loading ? <span className="spinner" /> : '▶ Run Sample Analysis'}
              </button>
            </div>
          </div>

          {/* Simulation */}
          <div>
            <div style={{ fontSize: 10, color: 'var(--mu)', letterSpacing: '.1em', marginBottom: 8 }}>
              GENERATE SIMULATION DATA
            </div>
            <div style={{
              border: '1px solid var(--border2)', borderRadius: 'var(--radius)',
              padding: 16, height: 'calc(100% - 22px)',
              display: 'flex', flexDirection: 'column', gap: 10,
            }}>
              <div style={{ fontSize: 28, textAlign: 'center' }}>⚗️</div>
              <select
                value={simType} onChange={e => setSimType(e.target.value)}
                style={{
                  background: 'var(--bg)', border: '1px solid var(--border2)',
                  borderRadius: 'var(--radius-sm)', padding: '6px 10px',
                  color: 'var(--tx)', fontFamily: 'var(--font-mono)', fontSize: 12, outline: 'none',
                }}
              >
                <option value="brute_force">Brute Force</option>
                <option value="credential_stuffing">Credential Stuffing</option>
                <option value="dictionary">Dictionary Attack</option>
                <option value="normal">Normal Logins</option>
              </select>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <label style={{ fontSize: 11, color: 'var(--mu)', whiteSpace: 'nowrap' }}>Events:</label>
                <input
                  type="number" value={simCount}
                  onChange={e => setSimCount(Number(e.target.value))}
                  min={5} max={100}
                  style={{
                    background: 'var(--bg)', border: '1px solid var(--border2)',
                    borderRadius: 'var(--radius-sm)', padding: '5px 8px',
                    color: 'var(--tx)', fontFamily: 'var(--font-mono)', fontSize: 12,
                    outline: 'none', width: '100%',
                  }}
                />
              </div>
              <button
                className="btn btn-danger" disabled={loading}
                onClick={() => onSimulate(simType, simCount)}
                style={{ width: '100%' }}
              >
                {loading ? <span className="spinner" /> : '⚡ Simulate Attack'}
              </button>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}
