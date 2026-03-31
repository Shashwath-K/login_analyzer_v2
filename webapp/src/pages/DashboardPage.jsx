import StatsRow from '../components/StatsRow.jsx'
import {
  AttackDistributionChart,
  AttemptsPerIPChart,
  SuccessVsFailureChart,
  AttemptsOverTimeChart,
} from '../components/Charts.jsx'

export default function DashboardPage({ data, loading }) {
  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 80, gap: 20 }}>
        <span className="spinner" style={{ width: 40, height: 40, borderWidth: 3 }} />
        <div style={{ color: 'var(--mu)', fontSize: 14 }}>Running ML analysis pipeline…</div>
      </div>
    )
  }

  if (!data) {
    return (
      <div style={{ paddingTop: 60, textAlign: 'center' }}>
        <div className="card" style={{ maxWidth: 560, margin: '0 auto' }}>
          <div className="card-body" style={{ padding: 40 }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>🔐</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--a1)', marginBottom: 10 }}>
              Login Attack Pattern Analyzer
            </div>
            <div style={{ color: 'var(--mu)', fontSize: 13, lineHeight: 1.8, marginBottom: 20 }}>
              ML-based authentication threat detection using<br />
              <strong style={{ color: 'var(--tx)' }}>RandomForestClassifier</strong> trained on login behavior features.
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center', fontSize: 12 }}>
              {['Brute Force Detection', 'Credential Stuffing', 'Dictionary Attacks',
                'Password Spray', 'ML Explainability', 'SOC Reports'].map(f => (
                <span key={f} className="pill">{f}</span>
              ))}
            </div>
            <div style={{
              marginTop: 24, padding: '12px 16px',
              background: 'rgba(0,240,200,.05)',
              border: '1px solid rgba(0,240,200,.15)',
              borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--mu)',
            }}>
              👆 Use the <strong style={{ color: 'var(--a1)' }}>Analysis</strong> tab to load data and run the pipeline.
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="fade-up">
      <StatsRow data={data} />

      <div className="grid-2">
        <SuccessVsFailureChart data={data} />
        <AttackDistributionChart data={data} />
      </div>

      <div style={{ marginTop: 14 }}>
        <AttemptsOverTimeChart data={data} />
      </div>

      <div style={{ marginTop: 14 }}>
        <AttemptsPerIPChart data={data} />
      </div>

      {!data.ml_available && (
        <div style={{
          marginTop: 16, padding: '14px 20px',
          background: 'rgba(245,166,35,.06)',
          border: '1px solid rgba(245,166,35,.25)',
          borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--a3)',
        }}>
          ⚠️ <strong>ML model not trained yet.</strong> Charts show only statistical data.
          Click <strong>Train Model</strong> in the header to enable attack classification.
        </div>
      )}
    </div>
  )
}
