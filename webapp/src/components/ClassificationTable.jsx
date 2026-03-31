import { useEffect, useState } from 'react'

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, INFO: 1, Normal: 0 }

export default function ClassificationTable({ data }) {
  const [search, setSearch]       = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [sortCol, setSortCol]     = useState('confidence')
  const [sortAsc, setSortAsc]     = useState(false)
  const [expanded, setExpanded]   = useState(null)

  const rows = (data?.classified_ips || [])
    .filter(r => {
      const q = search.toLowerCase()
      const matchQ = !q || r.ip.includes(q) || r.attack_type.toLowerCase().includes(q)
      const matchS = !sevFilter || r.severity === sevFilter
      return matchQ && matchS
    })
    .sort((a, b) => {
      let av = a[sortCol], bv = b[sortCol]
      if (sortCol === 'severity') { av = SEV_ORDER[av] || 0; bv = SEV_ORDER[bv] || 0 }
      if (typeof av === 'number') return sortAsc ? av - bv : bv - av
      return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av))
    })

  const toggleSort = col => { setSortAsc(sortCol === col ? !sortAsc : false); setSortCol(col) }
  const SortIcon = ({ col }) => sortCol === col ? (sortAsc ? ' ↑' : ' ↓') : ''

  return (
    <div className="card fade-up">
      <div className="card-header">
        <span>🎯</span>
        <span className="card-title" style={{ color: 'var(--a1)' }}>ML Classification Results</span>
        <span className="pill" style={{ marginLeft: 'auto' }}>{rows.length} / {data?.classified_ips?.length || 0} IPs</span>
      </div>
      <div className="card-body">
        {/* Filters */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="🔍 Search IP or attack type…"
            style={{
              background: 'var(--bg)', border: '1px solid var(--border2)',
              borderRadius: 'var(--radius-sm)', padding: '6px 12px',
              color: 'var(--tx)', fontFamily: 'var(--font-mono)', fontSize: 12, outline: 'none',
              flex: 1, minWidth: 200,
            }}
          />
          <select
            value={sevFilter} onChange={e => setSevFilter(e.target.value)}
            style={{
              background: 'var(--bg)', border: '1px solid var(--border2)',
              borderRadius: 'var(--radius-sm)', padding: '6px 10px',
              color: 'var(--tx)', fontFamily: 'var(--font-mono)', fontSize: 12, outline: 'none',
            }}
          >
            <option value="">All Severities</option>
            {['CRITICAL','HIGH','MEDIUM','INFO'].map(s => <option key={s}>{s}</option>)}
          </select>
        </div>

        {rows.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <div className="empty-text">No classification results yet. Run sample or upload a file.</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    ['ip', 'SOURCE IP'], ['attack_type', 'ATTACK TYPE'],
                    ['severity', 'SEVERITY'], ['confidence', 'CONFIDENCE'],
                    ['failed_attempts', 'FAILURES'], ['unique_usernames', 'USERNAMES'],
                    ['request_rate', 'RATE/s'],
                  ].map(([col, label]) => (
                    <th key={col} onClick={() => toggleSort(col)}
                      style={{ cursor: 'pointer' }}>
                      {label}<SortIcon col={col} />
                    </th>
                  ))}
                  <th>DETAILS</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <>
                    <tr key={r.ip}>
                      <td className="ip-text">{r.ip}</td>
                      <td>
                        <span style={{
                          color: r.attack_type === 'Normal' ? 'var(--info)'
                               : r.severity === 'CRITICAL' ? 'var(--crit)' : 'var(--high)',
                          fontWeight: 600, fontSize: 12,
                        }}>{r.attack_type}</span>
                      </td>
                      <td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{
                            width: 52, height: 4, background: 'var(--border)',
                            borderRadius: 2, overflow: 'hidden',
                          }}>
                            <div style={{
                              width: `${r.confidence}%`, height: '100%',
                              background: r.confidence > 80 ? 'var(--a1)' : 'var(--a3)',
                              borderRadius: 2,
                            }} />
                          </div>
                          <span style={{ color: 'var(--tx)', fontSize: 11 }}>{r.confidence}%</span>
                        </div>
                      </td>
                      <td className="mono">{r.failed_attempts}</td>
                      <td className="mono">{r.unique_usernames}</td>
                      <td className="mono" style={{ color: r.request_rate > 0.2 ? 'var(--a2)' : 'var(--tx)' }}>
                        {r.request_rate}
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 10px', fontSize: 11 }}
                          onClick={() => setExpanded(expanded === r.ip ? null : r.ip)}
                        >
                          {expanded === r.ip ? '▲ Hide' : '▼ Explain'}
                        </button>
                      </td>
                    </tr>
                    {expanded === r.ip && (
                      <tr key={`${r.ip}-exp`}>
                        <td colSpan={8} style={{ padding: 0 }}>
                          <div style={{ padding: '12px 18px', background: 'rgba(0,0,0,.25)' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                              <div>
                                <div style={{ fontSize: 11, color: 'var(--a5)', fontWeight: 600, marginBottom: 8, letterSpacing: '.06em' }}>
                                  WHY THIS CLASSIFICATION
                                </div>
                                <div className="reasons-list">
                                  {(r.reasons || []).map((reason, j) => (
                                    <div key={j} className="reason-item" style={{ marginBottom: 4 }}>{reason}</div>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <div style={{ fontSize: 11, color: 'var(--a3)', fontWeight: 600, marginBottom: 8, letterSpacing: '.06em' }}>
                                  RECOMMENDED ACTIONS
                                </div>
                                <ol style={{
                                  paddingLeft: 18, fontSize: 12, color: 'var(--tx)', lineHeight: 1.9,
                                  background: 'rgba(0,0,0,.3)', borderRadius: 'var(--radius-sm)',
                                  padding: '12px 16px 12px 28px',
                                  borderLeft: '3px solid var(--a3)',
                                }}>
                                  {(r.recommendation_steps || []).map((step, j) => (
                                    <li key={j} style={{ marginBottom: 4 }}>{step}</li>
                                  ))}
                                </ol>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
