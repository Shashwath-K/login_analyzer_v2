import { useState } from 'react'

const tabs = ['THREAT NARRATIVE', 'SOC REPORT', 'FIREWALL RULES', 'ALERT EMAILS']

export default function ReportsPanel({ data }) {
  const [tab, setTab] = useState(0)

  const contents = [
    data?.threat_narrative || '',
    data?.soc_report || '',
    data?.firewall_rules || '',
    data?.alert_emails || '',
  ]

  const copy = () => {
    navigator.clipboard.writeText(contents[tab])
      .then(() => { /* success */ })
      .catch(() => { /* fallback */ })
  }

  return (
    <div className="card fade-up">
      <div className="card-header">
        <span>📋</span>
        <span className="card-title" style={{ color: 'var(--a1)' }}>Reports & Actions</span>
      </div>
      <div className="card-body" style={{ padding: 0 }}>
        {/* Tab bar */}
        <div style={{
          display: 'flex', gap: 0,
          borderBottom: '1px solid var(--border)',
          background: 'rgba(0,0,0,.2)',
          overflowX: 'auto',
        }}>
          {tabs.map((t, i) => (
            <button
              key={t}
              onClick={() => setTab(i)}
              style={{
                padding: '10px 18px',
                background: 'transparent',
                border: 'none',
                borderBottom: i === tab ? '2px solid var(--a1)' : '2px solid transparent',
                color: i === tab ? 'var(--a1)' : 'var(--mu)',
                fontFamily: 'var(--font-ui)', fontWeight: 600,
                fontSize: 11, letterSpacing: '.07em', cursor: 'pointer',
                whiteSpace: 'nowrap', transition: '.15s',
              }}
            >
              {t}
            </button>
          ))}
          <div style={{ marginLeft: 'auto', padding: '6px 14px', display: 'flex', alignItems: 'center' }}>
            <button className="btn btn-ghost" onClick={copy} style={{ fontSize: 11, padding: '4px 12px' }}>
              📋 Copy
            </button>
          </div>
        </div>

        {/* Content */}
        <div style={{ padding: 18 }}>
          {!contents[tab] ? (
            <div className="empty-state">
              <div className="empty-icon">📄</div>
              <div className="empty-text">Run an analysis to generate {tabs[tab].toLowerCase()}.</div>
            </div>
          ) : (
            <div className="output-box">{contents[tab]}</div>
          )}
        </div>
      </div>
    </div>
  )
}
