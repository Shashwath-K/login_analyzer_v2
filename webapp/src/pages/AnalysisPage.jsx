import UploadPanel from '../components/UploadPanel.jsx'
import ClassificationTable from '../components/ClassificationTable.jsx'

export default function AnalysisPage({ data, loading, error, onFile, onSample, onSimulate }) {
  return (
    <div>
      <UploadPanel
        onFile={onFile}
        onSample={onSample}
        onSimulate={onSimulate}
        loading={loading}
      />

      {error && (
        <div style={{
          padding: '12px 18px', marginBottom: 16,
          background: 'rgba(255,45,107,.08)',
          border: '1px solid rgba(255,45,107,.3)',
          borderRadius: 'var(--radius)', color: 'var(--crit)', fontSize: 13,
        }}>
          ⚠️ <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 14,
          padding: '20px 24px', marginBottom: 14,
          background: 'var(--card)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
        }}>
          <span className="spinner" style={{ width: 22, height: 22 }} />
          <div>
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--a1)' }}>Running ML pipeline…</div>
            <div style={{ color: 'var(--mu)', fontSize: 11, marginTop: 3 }}>
              Reading logs → Extracting features → Classifying attacks → Generating explanations
            </div>
          </div>
        </div>
      )}

      {data && !loading && (
        <>
          {/* Quick summary bar */}
          <div style={{
            display: 'flex', gap: 14, flexWrap: 'wrap',
            marginBottom: 16, padding: '12px 16px',
            background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius)', alignItems: 'center',
          }}>
            <span style={{ fontSize: 12, color: 'var(--mu)' }}>Analysis complete.</span>
            {[
              { label: 'Events', val: data.total_events, color: 'var(--a1)' },
              { label: 'Failures', val: data.failures, color: 'var(--crit)' },
              { label: 'Attacker IPs', val: (data.classified_ips||[]).filter(r=>r.attack_type!=='Normal').length, color: 'var(--a3)' },
              { label: 'Unique IPs', val: data.unique_ips, color: 'var(--a4)' },
            ].map(s => (
              <span key={s.label} style={{ fontSize: 12 }}>
                <strong style={{ color: s.color, fontSize: 15 }}>{s.val}</strong>
                {' '}<span style={{ color: 'var(--mu)' }}>{s.label}</span>
              </span>
            ))}
            {!data.ml_available && (
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--a3)', padding: '3px 10px',
                background: 'rgba(245,166,35,.1)', border: '1px solid rgba(245,166,35,.25)',
                borderRadius: 12 }}>
                ⚠️ Model not trained — statistical analysis only
              </span>
            )}
          </div>

          <ClassificationTable data={data} />
        </>
      )}

      {!data && !loading && (
        <div className="card">
          <div className="card-body">
            <div className="empty-state">
              <div className="empty-icon">🎯</div>
              <div className="empty-text">
                Upload a CSV, run the sample, or simulate an attack above to see ML classification results.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
