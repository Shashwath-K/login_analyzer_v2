import { useEffect, useState } from 'react'
import Navbar from './components/Navbar.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import AnalysisPage from './pages/AnalysisPage.jsx'
import ReportsPage from './pages/ReportsPage.jsx'
import { useAnalysis } from './hooks/useAnalysis.js'

export default function App() {
  const [tab, setTab] = useState(0)
  const [toast, setToast] = useState({ msg: '', show: false })

  const {
    data, loading, error,
    modelReady, checkStatus,
    runSample, runUpload, trainModel, simulate,
  } = useAnalysis()

  // Check model status on mount
  useEffect(() => {
    checkStatus()
  }, [checkStatus])

  // Auto-switch to dashboard after data loads
  useEffect(() => {
    if (data && !loading) setTab(0)
  }, [data, loading])

  const showToast = (msg) => {
    setToast({ msg, show: true })
    setTimeout(() => setToast(t => ({ ...t, show: false })), 3200)
  }

  const handleTrain = async () => {
    await trainModel()
    showToast('✅ Model trained and saved to ml_model/model.pkl')
  }

  const handleSample = async () => {
    setTab(1)
    await runSample()
    showToast('✅ Sample analysis complete')
  }

  const handleFile = async (file) => {
    setTab(1)
    await runUpload(file)
    showToast(`✅ Analyzed ${file.name}`)
  }

  const handleSimulate = async (type, count) => {
    setTab(1)
    await simulate(type, count)
    showToast(`✅ Simulation: ${type.replace(/_/g, ' ')} (${count} events)`)
  }

  const pages = [
    <DashboardPage data={data} loading={loading} />,
    <AnalysisPage
      data={data} loading={loading} error={error}
      onFile={handleFile} onSample={handleSample} onSimulate={handleSimulate}
    />,
    <ReportsPage data={data} />,
  ]

  return (
    <div className="app-layout">
      {/* Scanline effect */}
      <div className="scanline" />

      <Navbar
        tab={tab} setTab={setTab}
        modelReady={modelReady}
        loading={loading}
        onTrain={handleTrain}
      />

      <main className="main-content">
        {pages[tab]}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border)',
        padding: '10px 32px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        fontSize: 10, color: 'var(--mu)',
      }}>
        <span>🔐 Login Attack Pattern Analyzer · ML-Based Threat Detection</span>
        <span>Python 3.10+ · scikit-learn · FastAPI · React 18 · Recharts</span>
      </footer>

      {/* Toast */}
      <div className={`toast${toast.show ? ' show' : ''}`}>{toast.msg}</div>
    </div>
  )
}
