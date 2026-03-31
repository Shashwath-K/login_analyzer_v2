export default function Navbar({ tab, setTab, modelReady, loading, onTrain }) {
  const navTabs = ['Dashboard', 'Analysis', 'Reports']

  return (
    <nav>
      <div className="nav-logo">
        🔐 <span>NetSentinel</span>
        <span style={{ color: 'var(--mu)', fontSize: 12, fontWeight: 400, marginLeft: 8 }}>
          ML Threat Detection
        </span>
      </div>

      <div className="nav-tabs">
        {navTabs.map((t, i) => (
          <button
            key={t}
            className={`nav-tab${tab === i ? ' active' : ''}`}
            onClick={() => setTab(i)}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="nav-right">
        {modelReady !== null && (
          <div className="status-dot">
            <div className={`dot ${modelReady ? 'dot-ok' : 'dot-off'}`} />
            <span style={{ fontSize: 10 }}>
              {modelReady ? 'Model Ready' : 'No Model'}
            </span>
          </div>
        )}

        {modelReady === false && (
          <button className="btn btn-primary" onClick={onTrain} disabled={loading}
            style={{ fontSize: 11, padding: '6px 14px' }}>
            {loading
              ? <><span className="spinner" style={{ width: 13, height: 13 }} /> Training…</>
              : '🧠 Train Model'
            }
          </button>
        )}
      </div>
    </nav>
  )
}
