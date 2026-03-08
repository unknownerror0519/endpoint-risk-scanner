import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import type { EndpointListItem } from '../types'
import { Button } from '../components/Button'
import { Card } from '../components/Card'
import { Badge } from '../components/Badge'

function formatWhen(iso?: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function formatTime(d: Date) {
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

const RefreshIcon = () => (
  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
)

const ScanIcon = () => (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
)

const ViewIcon = () => (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
  </svg>
)

const MonitorIcon = () => (
  <svg className="h-4 w-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
  </svg>
)

const SearchIcon = () => (
  <svg className="h-4 w-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
)

const Th = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <th className={`whitespace-nowrap px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 ${className}`}>{children}</th>
)

export function Dashboard() {
  const [items, setItems] = useState<EndpointListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const data = await api.listEndpoints(200)
      setItems(data)
      setLastRefresh(new Date())
    } catch (e: any) {
      setError(e?.message || 'Failed to load endpoints')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const scanningIds = useMemo(
    () => new Set(items.filter((i) => i.scan_status === 'scanning').map((i) => i.endpoint_id)),
    [items]
  )

  useEffect(() => {
    if (scanningIds.size === 0) return
    const t = window.setInterval(() => void load(), 3000)
    return () => window.clearInterval(t)
  }, [scanningIds.size])

  // General auto-refresh every 30 seconds to pick up agent updates
  useEffect(() => {
    const t = window.setInterval(() => void load(), 30_000)
    return () => window.clearInterval(t)
  }, [])

  async function onScan(endpointId: string) {
    setScanError(null)
    // Optimistically show scanning immediately.
    setItems((prev) => prev.map((it) => (it.endpoint_id === endpointId ? { ...it, scan_status: 'scanning' } : it)))
    try {
      await api.startScan(endpointId)
      // Best-effort refresh; polling kicks in while any endpoint is scanning.
      void load()
    } catch (e: any) {
      setScanError(e?.message || 'Failed to start scan')
      // Roll back optimistic state on failure.
      setItems((prev) => prev.map((it) => (it.endpoint_id === endpointId ? { ...it, scan_status: 'failed' } : it)))
    }
  }

  async function onCancel(endpointId: string) {
    setScanError(null)
    try {
      await api.cancelScan(endpointId)
      await load()
    } catch (e: any) {
      setScanError(e?.message || 'Failed to cancel scan')
    }
  }

  const onlineCount = items.filter((i) => i.is_online === true).length
  const offlineCount = items.filter((i) => i.is_online !== true).length

  const filtered = useMemo(() => {
    if (!search.trim()) return items
    const q = search.toLowerCase()
    return items.filter((it) => {
      const name = (it.endpoint_name || '').toLowerCase()
      const id = it.endpoint_id.toLowerCase()
      const os = (it.os_name || '').toLowerCase()
      return name.includes(q) || id.includes(q) || os.includes(q)
    })
  }, [items, search])

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      {/* Status summary bar */}
      <div className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            {onlineCount} Online
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-3 py-1 text-xs font-semibold text-red-700 ring-1 ring-inset ring-red-600/20">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
            {offlineCount} Offline
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span>Updated {formatTime(lastRefresh)}</span>
          <button
            onClick={() => void load()}
            className="rounded-md p-1 text-gray-400 transition hover:bg-gray-100 hover:text-gray-600"
            title="Refresh"
          >
            <RefreshIcon />
          </button>
        </div>
      </div>

      {/* Search bar */}
      <div className="mb-5">
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5">
            <SearchIcon />
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by hostname or OS..."
            className="block w-full rounded-lg border border-gray-200 bg-white py-2.5 pl-10 pr-4 text-sm text-gray-900 placeholder-gray-400 shadow-sm transition focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-100"
          />
        </div>
      </div>

      {/* Error banners */}
      {scanError && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <span className="mt-0.5 shrink-0">⚠</span>
          <span>{scanError}</span>
        </div>
      )}
      {error && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <span className="mt-0.5 shrink-0">⚠</span>
          <span>{error}</span>
        </div>
      )}

      {/* Devices table */}
      <Card noPadding>
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-700">
            Devices ({loading ? '…' : filtered.length})
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Status</Th>
                <Th>Hostname</Th>
                <Th>Operating System</Th>
                <Th>Last Seen</Th>
                <Th>Apps</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((it) => {
                const isScanning = it.scan_status === 'scanning'
                const online = it.is_online === true
                return (
                  <tr key={it.endpoint_id} className="transition-colors hover:bg-gray-50/70">
                    {/* Status */}
                    <td className="whitespace-nowrap px-5 py-4">
                      <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${online ? 'text-emerald-600' : 'text-red-500'}`}>
                        <span className={`h-2 w-2 rounded-full ${online ? 'bg-emerald-500' : 'bg-red-500'}`} />
                        {online ? 'Online' : 'Offline'}
                      </span>
                    </td>
                    {/* Hostname */}
                    <td className="whitespace-nowrap px-5 py-4">
                      <div className="flex items-center gap-2.5">
                        <MonitorIcon />
                        <div>
                          <Link
                            className="font-semibold text-gray-900 hover:text-indigo-600 hover:underline"
                            to={`/endpoints/${encodeURIComponent(it.endpoint_id)}`}
                          >
                            {it.endpoint_name || it.endpoint_id}
                          </Link>
                          <div className="mt-0.5 font-mono text-[11px] text-gray-400">{it.endpoint_id}</div>
                        </div>
                      </div>
                    </td>
                    {/* OS */}
                    <td className="whitespace-nowrap px-5 py-4 text-gray-600">
                      {it.os_name || 'Unknown'}
                    </td>
                    {/* Last Seen */}
                    <td className="whitespace-nowrap px-5 py-4 text-gray-500">
                      {formatWhen(it.last_seen)}
                    </td>
                    {/* Apps */}
                    <td className="whitespace-nowrap px-5 py-4">
                      <Badge label={`${it.application_count} apps`} tone="success" size="md" />
                    </td>
                    {/* Actions */}
                    <td className="whitespace-nowrap px-5 py-4 text-right">
                      <div className="inline-flex items-center gap-2">
                        <Link to={`/endpoints/${encodeURIComponent(it.endpoint_id)}`}>
                          <Button variant="secondary" size="sm" icon={<ViewIcon />}>View</Button>
                        </Link>
                        {isScanning ? (
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={() => void onCancel(it.endpoint_id)}
                            icon={<svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>}
                          >
                            Cancel
                          </Button>
                        ) : (
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={() => void onScan(it.endpoint_id)}
                            icon={<ScanIcon />}
                          >
                            Scan
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-gray-400">
                    {items.length === 0 ? 'No endpoints found in Firestore.' : 'No endpoints match your search.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
