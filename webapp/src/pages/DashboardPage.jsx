import { ShieldCheck, ArrowRight, BarChart3, Activity } from 'lucide-react'
import StatsRow from '../components/StatsRow.jsx'
import Charts from '../components/Charts.jsx'

export default function DashboardPage({ data, loading }) {
  if (!data && !loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: '60vh', textAlign: 'center' }}>
        <div className="card" style={{ maxWidth: 460, padding: 40, background: 'var(--panel)' }}>
          <ShieldCheck size={64} color="var(--a1)" style={{ marginBottom: 24, opacity: 0.8 }} />
          <p style={{ color: 'var(--mu)', fontSize: 14, lineHeight: 1.6, marginBottom: 32 }}>
            A professional pattern-driven authentication threat intelligence platform. 
            Upload your system logs to identify brute force, credential stuffing, and dictionary attack patterns with explainable analysis logic.
          </p>
          <div className="flex justify-center gap-4">
            <div style={{ padding: '12px 20px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 13, background: 'rgba(255,255,255,0.02)' }}>
               ML-Based Attack Classification
            </div>
            <div style={{ padding: '12px 20px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 13, background: 'rgba(255,255,255,0.02)' }}>
               Plain-English Reasonings
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="fade-up">
      <div className="flex items-center justify-between" style={{ marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em' }}>Security Overview</h1>
          <p style={{ color: 'var(--mu)', fontSize: 13, marginTop: 4 }}>Real-time authentication threat intelligence and risk assessment.</p>
        </div>
        <div className="flex items-center gap-2" style={{ color: 'var(--a4)', fontSize: 12, fontWeight: 600 }}>
          <Activity size={14} />
          <span>System Monitoring Active</span>
        </div>
      </div>

      <StatsRow data={data} />
      
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <BarChart3 size={16} color="var(--a1)" />
            <span className="card-title">Threat Distribution</span>
          </div>
          <div className="card-body chart-bg">
            <Charts data={data} type="pie" />
          </div>
        </div>
        <div className="card">
          <div className="card-header">
            <Activity size={16} color="var(--a2)" />
            <span className="card-title">Authentication Success vs Failure</span>
          </div>
          <div className="card-body chart-bg">
            <Charts data={data} type="bar" />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
           <Activity size={16} color="var(--a1)" />
           <span className="card-title">Log Activity Intensity (Last 24h)</span>
        </div>
        <div className="card-body chart-bg" style={{ minHeight: 320 }}>
          <Charts data={data} type="area" />
        </div>
      </div>
    </div>
  )
}
