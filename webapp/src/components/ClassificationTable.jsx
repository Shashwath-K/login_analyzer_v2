import React, { useState, Fragment } from 'react'
import { Info, AlertTriangle, ChevronDown, ChevronUp, ShieldCheck, Zap, Key, Search } from 'lucide-react'

export default function ClassificationTable({ data }) {
  const [expanded, setExpanded] = useState(null)

  const rows = data?.classified_ips || []
  const attackers = rows.filter(r => r.attack_type !== 'Normal')

  if (attackers.length === 0) {
    return (
      <div className="card-body text-center" style={{ padding: '60px 20px', color: 'var(--mu)' }}>
        <ShieldCheck size={48} style={{ marginBottom: 16, opacity: 0.2 }} />
        <div style={{ fontSize: 16, fontWeight: 600 }}>No Security Threats Detected</div>
        <div style={{ fontSize: 13, marginTop: 4 }}>LogCentric analysis found no suspicious authentication patterns in this dataset.</div>
      </div>
    )
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 40 }}></th>
            <th>Attacker IP</th>
            <th>Classification</th>
            <th>Severity</th>
            <th>Failures</th>
            <th>Confidence</th>
            <th>Features / Action</th>
          </tr>
        </thead>
        <tbody>
          {attackers.map((r, idx) => (
            <Fragment key={r.ip}>
              <tr 
                onClick={() => setExpanded(expanded === idx ? null : idx)}
                style={{ cursor: 'pointer' }}
              >
                <td>{expanded === idx ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                <td className="ip-text">{r.ip}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    {r.attack_type === 'Brute Force' ? <Zap size={13} color="var(--crit)" /> :
                     r.attack_type === 'Dictionary' ? <Key size={13} color="var(--a5)" /> :
                     r.attack_type === 'Credential Stuffing' ? <Search size={13} color="var(--high)" /> :
                     <ShieldCheck size={13} />}
                    {r.attack_type}
                  </div>
                </td>
                <td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td>
                <td className="mono">{r.failed_attempts}</td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="progress-bar" style={{ width: 40 }}>
                      <div className="progress-fill" style={{ width: `${r.confidence}%` }} />
                    </div>
                    <span className="mono">{r.confidence}%</span>
                  </div>
                </td>
                <td style={{ color: 'var(--mu)', fontSize: 11 }}>
                   {r.unique_usernames} users · {r.request_rate} /sec
                </td>
              </tr>
              {expanded === idx && (
                <tr>
                  <td colSpan="7" style={{ padding: '0 20px 20px 60px', background: 'rgba(0,0,0,.15)' }}>
                    <div className="reasons-list fade-up">
                      <div style={{ fontWeight: 700, marginBottom: 8, color: 'var(--a1)', fontSize: 11, textTransform: 'uppercase' }}>ML Analysis Reasoning</div>
                      <div style={{ marginBottom: 12 }}>{r.summary}</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                        <div>
                          <div style={{ color: 'var(--mu)', fontWeight: 700, fontSize: 10, textTransform: 'uppercase', marginBottom: 4 }}>Identified Patterns</div>
                          {r.reasons.map((reason, i) => (
                            <div key={i} className="reason-item">{reason}</div>
                          ))}
                        </div>
                        <div>
                          <div style={{ color: 'var(--mu)', fontWeight: 700, fontSize: 10, textTransform: 'uppercase', marginBottom: 4 }}>Mitigation Roadmap</div>
                          {r.recommendation_steps.map((step, i) => (
                            <div key={i} style={{ display: 'flex', gap: 8, fontSize: 11, marginBottom: 4 }}>
                              <span style={{ color: 'var(--a4)' }}>✓</span>
                              <span>{step}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
