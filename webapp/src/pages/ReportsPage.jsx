import ReportsPanel from '../components/ReportsPanel.jsx'

export default function ReportsPage({ data }) {
  if (!data) {
    return (
      <div className="card">
        <div className="card-body">
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <div className="empty-text">
              Run an analysis on the <strong style={{ color: 'var(--a1)' }}>Analysis</strong> tab first to generate reports.
            </div>
          </div>
        </div>
      </div>
    )
  }

  const attackers = (data.classified_ips || []).filter(r => r.attack_type !== 'Normal')
  const criticals = attackers.filter(r => r.severity === 'CRITICAL')

  return (
    <div className="fade-up">
      {/* Threat level banner */}
      <div style={{
        marginBottom: 18, padding: '14px 20px',
        background: criticals.length >= 3
          ? 'rgba(255,45,107,.08)'  : attackers.length > 0
          ? 'rgba(245,166,35,.07)' : 'rgba(0,240,200,.05)',
        border: `1px solid ${criticals.length >= 3 ? 'rgba(255,45,107,.3)' : attackers.length > 0
          ? 'rgba(245,166,35,.25)' : 'rgba(0,240,200,.15)'}`,
        borderRadius: 'var(--radius)',
        display: 'flex', alignItems: 'center', gap: 14,
      }}>
        <span style={{ fontSize: 24 }}>
          {criticals.length >= 3 ? '🔴' : attackers.length > 0 ? '🟠' : '🟢'}
        </span>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14,
            color: criticals.length >= 3 ? 'var(--crit)' : attackers.length > 0 ? 'var(--a3)' : 'var(--a1)' }}>
            {criticals.length >= 3 ? 'CRITICAL THREAT LEVEL' :
             attackers.length > 0 ? 'ELEVATED THREAT LEVEL' : 'LOW THREAT LEVEL'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--mu)', marginTop: 2 }}>
            {attackers.length} attacker IP(s) detected · {criticals.length} critical · {data.total_events} total events
          </div>
        </div>
        <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
          <div style={{ fontSize: 11, color: 'var(--mu)' }}>Overall Risk</div>
          <div style={{
            fontSize: 18, fontWeight: 800,
            color: criticals.length >= 3 ? 'var(--crit)' : attackers.length > 0 ? 'var(--a3)' : 'var(--a1)',
          }}>
            {criticals.length >= 3 ? 'CRITICAL' : attackers.length > 0 ? 'HIGH' : 'LOW'}
          </div>
        </div>
      </div>

      {/* Attacker summary grid */}
      {attackers.length > 0 && (
        <div className="card" style={{ marginBottom: 18 }}>
          <div className="card-header">
            <span>⚡</span>
            <span className="card-title" style={{ color: 'var(--a2)' }}>Attacker Summary</span>
          </div>
          <div className="card-body">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
              {attackers.slice(0, 12).map(r => (
                <div key={r.ip} style={{
                  background: 'rgba(0,0,0,.3)',
                  border: `1px solid ${r.severity === 'CRITICAL' ? 'rgba(255,45,107,.3)' : 'rgba(245,166,35,.25)'}`,
                  borderRadius: 8, padding: '10px 14px', minWidth: 220,
                }}>
                  <div style={{ color: 'var(--a1)', fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600 }}>
                    {r.ip}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 5, alignItems: 'center' }}>
                    <span style={{
                      fontSize: 11, fontWeight: 700, color:
                        r.severity === 'CRITICAL' ? 'var(--crit)' : 'var(--high)' }}>
                      {r.attack_type}
                    </span>
                    <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--mu)', marginTop: 4 }}>
                    {r.failed_attempts} failures · {r.confidence}% confidence
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <ReportsPanel data={data} />
    </div>
  )
}
