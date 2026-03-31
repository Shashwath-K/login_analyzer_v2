import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  LineChart, Line, Area, AreaChart,
} from 'recharts'

const COLORS = {
  'Brute Force':         '#ff2d6b',
  'Credential Stuffing': '#f5a623',
  'Dictionary Attack':   '#c084fc',
  'Password Spray':      '#3d8eff',
  'Normal':              '#00f0c8',
  'Unknown':             '#556688',
}
const PIE_COLORS = Object.values(COLORS)

const DARK = {
  background: 'transparent',
  text: '#b8cce4',
  grid: '#131e35',
  tooltip: { bg: '#080d18', border: '#1a2845' },
}

const TT = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: DARK.tooltip.bg, border: `1px solid ${DARK.tooltip.border}`,
      borderRadius: 8, padding: '10px 14px', fontSize: 12, color: DARK.text,
    }}>
      {label && <div style={{ fontWeight: 700, marginBottom: 6, color: '#00f0c8' }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.fill, marginBottom: 2 }}>
          {p.name}: <strong>{typeof p.value === 'number' && p.value % 1 !== 0 ? p.value.toFixed(3) : p.value}</strong>
        </div>
      ))}
    </div>
  )
}

/* ── 1. Attack type pie ─────────────────────────────────────────────────────── */
export function AttackDistributionChart({ data }) {
  const items = (data?.attack_distribution || []).filter(d => d.count > 0)
  if (!items.length) return null
  return (
    <div className="chart-bg fade-up">
      <div className="chart-title">Attack Type Distribution</div>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart>
          <Pie
            data={items} dataKey="count" nameKey="type"
            cx="50%" cy="50%" outerRadius={95} innerRadius={52}
            labelLine={false}
            label={({ type, percent }) =>
              percent > 0.04 ? `${(percent * 100).toFixed(0)}%` : ''
            }
          >
            {items.map((d, i) => (
              <Cell key={d.type}
                fill={COLORS[d.type] || PIE_COLORS[i % PIE_COLORS.length]}
                stroke="transparent" />
            ))}
          </Pie>
          <Tooltip content={<TT />} />
          <Legend
            iconType="circle" iconSize={8}
            formatter={(v) => <span style={{ color: DARK.text, fontSize: 11 }}>{v}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ── 2. Top IPs bar ─────────────────────────────────────────────────────────── */
export function AttemptsPerIPChart({ data }) {
  const items = (data?.top_ips || []).slice(0, 10).map(d => ({
    ...d, colorClass: d.count >= 10 ? '#ff2d6b' : d.count >= 5 ? '#f5a623' : '#3d8eff',
  }))
  if (!items.length) return null
  return (
    <div className="chart-bg fade-up">
      <div className="chart-title">Failed Attempts per Source IP</div>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={items} layout="vertical" margin={{ left: 12, right: 16 }}>
          <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke={DARK.grid} />
          <XAxis type="number" tick={{ fill: DARK.text, fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="ip" tick={{ fill: '#00f0c8', fontSize: 10, fontFamily: 'JetBrains Mono' }}
            width={110} axisLine={false} tickLine={false} />
          <Tooltip content={<TT />} cursor={{ fill: 'rgba(0,240,200,.04)' }} />
          <Bar dataKey="count" name="Failed Logins" radius={[0, 3, 3, 0]}>
            {items.map((d, i) => <Cell key={i} fill={d.colorClass} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ── 3. Success vs Failure bar ──────────────────────────────────────────────── */
export function SuccessVsFailureChart({ data }) {
  if (!data) return null
  const items = [
    { name: 'Successful Logins', value: data.successes, color: '#00f0c8' },
    { name: 'Failed Logins',     value: data.failures,  color: '#ff2d6b' },
  ]
  return (
    <div className="chart-bg fade-up">
      <div className="chart-title">Login Outcome Summary</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={items} margin={{ left: -10, right: 10 }}>
          <CartesianGrid vertical={false} strokeDasharray="3 3" stroke={DARK.grid} />
          <XAxis dataKey="name" tick={{ fill: DARK.text, fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: DARK.text, fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip content={<TT />} cursor={{ fill: 'rgba(0,240,200,.03)' }} />
          <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]}>
            {items.map((d, i) => <Cell key={i} fill={d.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ── 4. Time series ─────────────────────────────────────────────────────────── */
export function AttemptsOverTimeChart({ data }) {
  const items = data?.time_series || []
  if (!items.length) return null
  const formatted = items.map(d => ({ ...d, time: d.time.split(' ')[1] || d.time }))
  return (
    <div className="chart-bg fade-up">
      <div className="chart-title">Login Attempts Over Time (30-min buckets)</div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={formatted} margin={{ right: 10 }}>
          <defs>
            <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ff2d6b" stopOpacity={0.2} />
              <stop offset="95%" stopColor="#ff2d6b" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="succGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00f0c8" stopOpacity={0.12} />
              <stop offset="95%" stopColor="#00f0c8" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={DARK.grid} />
          <XAxis dataKey="time" tick={{ fill: DARK.text, fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: DARK.text, fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip content={<TT />} />
          <Area type="monotone" dataKey="failures" name="Failed" stroke="#ff2d6b"
            fill="url(#failGrad)" strokeWidth={2} dot={false} />
          <Area type="monotone" dataKey="successes" name="Success" stroke="#00f0c8"
            fill="url(#succGrad)" strokeWidth={2} dot={false} strokeDasharray="5 3" />
          <Legend
            iconType="line" iconSize={12}
            formatter={v => <span style={{ color: DARK.text, fontSize: 10 }}>{v}</span>}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
