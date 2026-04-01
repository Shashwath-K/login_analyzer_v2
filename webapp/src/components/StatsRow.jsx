import { Activity, ShieldAlert, Users, AlertCircle, ShieldCheck } from 'lucide-react'

export default function StatsRow({ data }) {
  const stats = [
    { label: 'Total Events', value: data?.total_events || 0, sub: 'Log processed', icon: <Activity size={20} />, color: 'c1' },
    { label: 'Failed Logins', value: data?.failures || 0, sub: 'Security alerts', icon: <ShieldAlert size={20} />, color: 'c2' },
    { label: 'Attacker IPs', value: data?.unique_ips || 0, sub: 'Unique sources', icon: <Users size={20} />, color: 'c3' },
    { label: 'Critical Threats', value: data?.classified_ips?.filter(ip => ip.severity === 'CRITICAL').length || 0, sub: 'Immediate Action', icon: <AlertCircle size={20} />, color: 'c4' },
    { label: 'Successful Logins', value: data?.successes || 0, sub: 'Legitimate traffic', icon: <ShieldCheck size={20} />, color: 'c5' },
  ]

  return (
    <div className="stats-grid">
      {stats.map((s, i) => (
        <div key={i} className={`stat-card ${s.color}`}>
          <div className="flex justify-between items-center" style={{ marginBottom: 12 }}>
            <div className="stat-icon" style={{ opacity: 0.8 }}>{s.icon}</div>
            <div className="stat-label">{s.label}</div>
          </div>
          <div className="stat-value">{s.value.toLocaleString()}</div>
          <div className="stat-sub">{s.sub}</div>
        </div>
      ))}
    </div>
  )
}
