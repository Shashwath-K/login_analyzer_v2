import { ShieldAlert, AlertCircle, CheckCircle, FileText, Activity } from 'lucide-react'
import ReportsPanel from '../components/ReportsPanel.jsx'

export default function ReportsPage({ data }) {
  if (!data) {
    return (
      <div className="card">
        <div className="card-body">
          <div className="empty-state">
            <div className="empty-icon"><FileText size={48} color="var(--border2)" /></div>
            <div className="empty-text">
              Run an analysis on the <strong style={{ color: 'var(--a1)' }}>Analysis</strong> tab first to generate security intelligence reports.
            </div>
          </div>
        </div>
      </div>
    )
  }

  const attackers = (data.classified_ips || []).filter(r => r.attack_type !== 'Normal')
  const criticals = attackers.filter(r => r.severity === 'CRITICAL')

  const riskLevel = criticals.length >= 3 ? 'CRITICAL' : attackers.length > 0 ? 'HIGH' : 'LOW'
  const RiskIcon = criticals.length >= 3 ? ShieldAlert : attackers.length > 0 ? AlertCircle : CheckCircle
  const riskColor = criticals.length >= 3 ? 'var(--crit)' : attackers.length > 0 ? 'var(--high)' : 'var(--a4)'

  return (
    <div className="fade-up">
      {/* Threat level banner */}
      <div style={{
        marginBottom: 24, padding: '16px 24px',
        background: 'var(--panel)',
        border: `1px solid ${riskColor}33`,
        borderLeft: `4px solid ${riskColor}`,
        borderRadius: 'var(--radius)',
        display: 'flex', alignItems: 'center', gap: 16,
      }}>
        <RiskIcon size={32} color={riskColor} />
        <div>
          <div style={{ fontWeight: 800, fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.05em', color: riskColor }}>
            {riskLevel} Risk System State
          </div>
          <div style={{ fontSize: 13, color: 'var(--mu)', marginTop: 2 }}>
            {attackers.length} identified attacker IP(s) · {criticals.length} critical threats · {data.total_events} events analyzed
          </div>
        </div>
        <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--mu)', textTransform: 'uppercase' }}>Consolidated Risk Score</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: riskColor }}>{riskLevel}</div>
        </div>
      </div>

      {/* Attacker summary grid */}
      {attackers.length > 0 && (
        <div className="card">
          <div className="card-header">
            <Activity size={16} color="var(--a1)" />
            <span className="card-title">Threat Actor Landscape</span>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }}>
              {attackers.slice(0, 12).map(r => (
                <div key={r.ip} style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: `1px solid var(--border)`,
                  borderRadius: 10, padding: '12px 16px',
                }}>
                  <div style={{ color: 'var(--a1)', fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }}>
                    {r.ip}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: r.severity === 'CRITICAL' ? 'var(--crit)' : 'var(--high)' }}>
                      {r.attack_type}
                    </span>
                    <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--mu)', marginTop: 4 }}>
                    {r.failed_attempts} events · {r.confidence}% confidence
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
