import { useState, useCallback } from 'react'
import axios from 'axios'

const API = '/api'

export function useAnalysis() {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [modelReady, setModelReady] = useState(null)

  const checkStatus = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/status`)
      setModelReady(res.data.model_available)
      return res.data
    } catch { setModelReady(false); return null }
  }, [])

  const runSample = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const res = await axios.get(`${API}/sample`)
      setData(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load sample data.')
    } finally { setLoading(false) }
  }, [])

  const runUpload = useCallback(async (file) => {
    setLoading(true); setError(null)
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await axios.post(`${API}/analyze`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      setData(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'File upload failed.')
    } finally { setLoading(false) }
  }, [])

  const trainModel = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      await axios.post(`${API}/train`)
      setModelReady(true)
    } catch (e) {
      setError(e.response?.data?.detail || 'Training failed.')
    } finally { setLoading(false) }
  }, [])

  const simulate = useCallback(async (type, count = 20) => {
    setLoading(true); setError(null)
    try {
      const res = await axios.post(`${API}/simulate/${type}?count=${count}`)
      setData(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Simulation failed.')
    } finally { setLoading(false) }
  }, [])

  return { data, loading, error, modelReady, checkStatus, runSample, runUpload, trainModel, simulate }
}
