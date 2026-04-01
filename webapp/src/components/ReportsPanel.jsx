import { useState } from 'react'
import { FileText, ShieldAlert, Terminal, MessageSquareOff, Copy, ClipboardCheck } from 'lucide-react'

export default function ReportsPanel({ data }) {
  const [activeTab, setActiveTab] = useState(0)
  const [copied, setCopied] = useState(false)

  const tabs = [
    { label: 'Threat Narrative', icon: <MessageSquareOff size={14} />, content: data?.threat_narrative },
    { label: 'SOC Report', icon: <FileText size={14} />, content: data?.soc_report },
    { label: 'Firewall Rules', icon: <Terminal size={14} />, content: data?.firewall_rules },
    { label: 'Alert Emails', icon: <ShieldAlert size={14} />, content: data?.alert_emails }
  ]

  const handleCopy = () => {
    navigator.clipboard.writeText(tabs[activeTab].content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (!data) return (
    <div className="card-body text-center" style={{ padding: '40px 20px', color: 'var(--mu)' }}>
       No analysis reports generated yet.
    </div>
  )

  return (
    <div className="card">
      <div className="card-header justify-between">
        <div className="flex items-center gap-2">
          <FileText size={16} color="var(--a1)" />
          <span className="card-title">Security Intelligence Reports</span>
        </div>
        <button className="btn btn-ghost" onClick={handleCopy} style={{ fontSize: 11, padding: '4px 10px' }}>
          {copied ? <ClipboardCheck size={14} color="var(--a4)" /> : <Copy size={14} />}
          <span style={{ marginLeft: 6 }}>{copied ? 'Copied' : 'Copy Report'}</span>
        </button>
      </div>
      <div className="card-body">
        <div className="reports-tabs">
          {tabs.map((t, idx) => (
            <div 
              key={t.label} 
              className={`report-tab-btn${activeTab === idx ? ' active' : ''}`}
              onClick={() => setActiveTab(idx)}
            >
              {t.label}
            </div>
          ))}
        </div>
        <div className="output-box fade-up">
          {tabs[activeTab].content || 'No content available for this report section.'}
        </div>
      </div>
    </div>
  )
}
