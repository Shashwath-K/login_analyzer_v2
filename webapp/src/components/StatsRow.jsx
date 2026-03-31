export default function StatsRow({ data }) {
  if (!data) return null
  const attackers = (data.classified_ips || []).filter(r => r.attack_type !== 'Normal').length
  const criticals = (data.classified_ips || []).filter(r => r.severity === 'CRITICAL').length
  const high      = (data.classified_ips || []).filter(r => r.severity === 'HIGH').length
  const failPct   = data.total_events > 0
    ? ((data.failures / data.total_events) * 100).toFixed(1) : '0.0'

  const cards = [
    { label: 'TOTAL EVENTS',     value: data.total_events, sub: `${data.unique_ips} unique IPs`, color: 'c1' },
    { label: 'FAILED LOGINS',    value: data.failures,     sub: `${failPct}% failure rate`,     color: 'c2' },
    { label: 'ATTACKER IPs',     value: attackers,         sub: `ML-classified threats`,         color: 'c3' },
    { label: 'CRITICAL THREATS', value: criticals,         sub: `${high} HIGH severity`,         color: 'c4' },
    { label: 'SUCCESSFUL LOGINS',value: data.successes,    sub: `${(100 - failPct).toFixed(1)}% success`, color: 'c5' },
  ]

  return (
    <div className="stats-grid fade-up">
      {cards.map(c => (
        <div key={c.label} className={`stat-card ${c.color}`}>
          <div className="stat-label">{c.label}</div>
          <div className="stat-value">{c.value}</div>
          <div className="stat-sub">{c.sub}</div>
        </div>
      ))}
    </div>
  )
}
