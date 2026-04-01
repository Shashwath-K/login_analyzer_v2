import React from 'react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area
} from 'recharts'

/* ── LogCentric Chart Styling ───────────────────────────────────────────────── */
const THEME = {
  a1: '#38bdf8',   /* Light Blue */
  a2: '#ef4444',   /* Red */
  a3: '#f59e0b',   /* Orange */
  a4: '#22c55e',   /* Green */
  a5: '#8b5cf6',   /* Purple */
  bg: '#020617',
  text: '#94a3b8',
  grid: '#1e293b',
}

const COLORS = [THEME.a1, THEME.a2, THEME.a3, THEME.a5, THEME.a4]

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 8, padding: '10px 14px', fontSize: 12, color: '#f1f5f9',
      boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
    }}>
      {label && <div style={{ fontWeight: 700, marginBottom: 6, color: THEME.a1, textTransform: 'uppercase', fontSize: 10 }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.fill, marginBottom: 2, display: 'flex', gap: 8, justifyContent: 'space-between' }}>
          <span>{p.name}:</span> 
          <strong style={{ color: '#fff' }}>{typeof p.value === 'number' && p.value % 1 !== 0 ? p.value.toFixed(2) : p.value.toLocaleString()}</strong>
        </div>
      ))}
    </div>
  )
}

/* ── Specific Chart Implementations ─────────────────────────────────────────── */

function AttackDistributionPie({ data }) {
  const items = (data?.attack_distribution || []).filter(d => d.count > 0)
  if (!items.length) return <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center', color: THEME.text, fontSize: 12 }}>No attack data available</div>

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={items} dataKey="count" nameKey="type"
          cx="50%" cy="50%" outerRadius={85} innerRadius={55}
          paddingAngle={4} stroke="none"
        >
          {items.map((d, i) => (
            <Cell key={d.type} fill={COLORS[i % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend 
          iconType="circle" iconSize={8} align="center"
          formatter={(v) => <span style={{ color: THEME.text, fontSize: 11, marginLeft: 4 }}>{v}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

function OutcomeBar({ data }) {
  const items = [
    { name: 'Successful', value: data?.successes || 0, fill: THEME.a4 },
    { name: 'Failed', value: data?.failures || 0, fill: THEME.a2 }
  ]
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={items} margin={{ top: 10, right: 10, bottom: 20 }}>
        <CartesianGrid vertical={false} strokeDasharray="3 3" stroke={THEME.grid} />
        <XAxis dataKey="name" tick={{ fill: THEME.text, fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: THEME.text, fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.02)' }} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={40} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function TimeActivityArea({ data }) {
  const items = data?.time_series || []
  if (!items.length) return <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center', color: THEME.text, fontSize: 12 }}>No time-series data available</div>

  const formatted = items.map(d => ({ ...d, timeDisplay: d.time.split(' ')[1] || d.time }))
  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={formatted} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={THEME.a2} stopOpacity={0.2} />
            <stop offset="95%" stopColor={THEME.a2} stopOpacity={0} />
          </linearGradient>
          <linearGradient id="succGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={THEME.a1} stopOpacity={0.1} />
            <stop offset="95%" stopColor={THEME.a1} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={THEME.grid} vertical={false} />
        <XAxis dataKey="timeDisplay" tick={{ fill: THEME.text, fontSize: 10 }} axisLine={false} tickLine={false} dy={10} />
        <YAxis tick={{ fill: THEME.text, fontSize: 10 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Area type="monotone" dataKey="failures" name="Failed Attempts" stroke={THEME.a2} fill="url(#failGrad)" strokeWidth={2} dot={false} />
        <Area type="monotone" dataKey="successes" name="Successful Logins" stroke={THEME.a4} fill="url(#succGrad)" strokeWidth={2} dot={false} strokeDasharray="5 5" />
        <Legend 
            verticalAlign="top" iconType="rect" align="right"
            formatter={(v) => <span style={{ color: THEME.text, fontSize: 10 }}>{v}</span>}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

/* ── Default Export Dispatcher ──────────────────────────────────────────────── */

export default function Charts({ data, type }) {
  if (type === 'pie') return <AttackDistributionPie data={data} />
  if (type === 'bar') return <OutcomeBar data={data} />
  if (type === 'area') return <TimeActivityArea data={data} />
  return null
}

export { AttackDistributionPie, OutcomeBar, TimeActivityArea }
