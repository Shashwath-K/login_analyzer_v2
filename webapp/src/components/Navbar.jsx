import { ShieldAlert, BarChart3, Search, FileText, Settings, Cpu } from 'lucide-react'

export default function Navbar({ tab, setTab, modelReady, loading, onTrain }) {
  const tabs = [
    { label: 'Dashboard', icon: <BarChart3 size={16} /> },
    { label: 'Analysis', icon: <Search size={16} /> },
    { label: 'Reports', icon: <FileText size={16} /> }
  ]

  return (
    <nav>
      <div className="nav-logo">
        <ShieldAlert className="logo-icon" size={24} />
        <span>LogCentric</span>
      </div>

      <div className="nav-tabs">
        {tabs.map((t, idx) => (
          <div
            key={t.label}
            className={`nav-tab${tab === idx ? ' active' : ''}`}
            onClick={() => setTab(idx)}
          >
            {t.icon}
            <span style={{ marginLeft: 8 }}>{t.label}</span>
          </div>
        ))}
      </div>

      <div className="nav-right">
        <div className={`status-pill${modelReady ? ' ready' : ''}`}>
          <Cpu size={14} />
          <span>{modelReady ? 'Model Ready' : 'Model Missing'}</span>
        </div>
        
        <button 
          className="btn btn-outline" 
          onClick={onTrain}
          disabled={loading}
          style={{ height: 32, padding: '0 12px' }}
        >
          {loading ? 'Training...' : 'Retrain Model'}
        </button>
      </div>
    </nav>
  )
}
