import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../lib/api'
import type { EndpointResults, EndpointDetail, ApplicationCves, CveDetail } from '../types'
import { Button } from '../components/Button'
import { Card } from '../components/Card'
import { RiskPill, riskColor } from '../components/RiskPill'
import { Badge } from '../components/Badge'

/* ─── helpers ─── */
function formatWhen(iso?: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/* ─── icons ─── */
const ArrowLeftIcon = () => (
  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="19" y1="12" x2="5" y2="12" /><polyline points="12 19 5 12 12 5" />
  </svg>
)
const RefreshIcon = () => (
  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
)
const Spinner = () => (
  <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
  </svg>
)
const XIcon = () => (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
  </svg>
)

/* ─── shared row / stat helpers ─── */
function StatBox({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50/50 px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`mt-1 text-lg font-bold tabular-nums ${color || 'text-gray-900'}`}>{value}</p>
    </div>
  )
}
function InfoRow({ label, value }: { label: string; value?: string | number | null | boolean }) {
  if (value === undefined || value === null || value === '') return null
  const display = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <span className="text-xs font-medium text-gray-500 shrink-0">{label}</span>
      <span className="text-sm text-gray-900 text-right break-all">{display}</span>
    </div>
  )
}
function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-3 mt-1">{children}</h3>
}

/* table header cell */
const Th = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <th className={`whitespace-nowrap px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 ${className}`}>{children}</th>
)

/* ─── tab definitions ─── */
const TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'security', label: 'Security' },
  { key: 'network', label: 'Network' },
  { key: 'software', label: 'Software' },
  { key: 'activity', label: 'Activity' },
  { key: 'scan', label: 'Scan Results' },
] as const
type TabKey = (typeof TABS)[number]['key']

/* ─── scan progress banner ─── */
function ScanProgressBanner({ onCancel, cancelling }: { onCancel: () => void; cancelling: boolean }) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    const t = window.setInterval(() => setElapsed((e) => e + 1), 1000)
    return () => window.clearInterval(t)
  }, [])
  const mins = Math.floor(elapsed / 60)
  const secs = elapsed % 60
  const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`

  return (
    <div className="mb-6 overflow-hidden rounded-xl border border-blue-200 bg-gradient-to-r from-blue-50 to-indigo-50 shadow-sm">
      <div className="px-5 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-100"><Spinner /></div>
            <div>
              <p className="text-sm font-semibold text-blue-900">Vulnerability scan in progress</p>
              <p className="mt-0.5 text-xs text-blue-600">Querying NVD database, enriching CVEs, scoring with ML model…</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-semibold tabular-nums text-blue-700">{timeStr}</span>
            <Button variant="danger" size="sm" onClick={onCancel} disabled={cancelling} icon={cancelling ? <Spinner /> : <XIcon />}>
              {cancelling ? 'Cancelling…' : 'Cancel'}
            </Button>
          </div>
        </div>
      </div>
      <div className="h-1.5 w-full bg-blue-100">
        <div className="h-full animate-scan-progress rounded-r bg-gradient-to-r from-blue-500 to-indigo-500" />
      </div>
    </div>
  )
}

/* ═══════════════ TAB PANELS ═══════════════ */

function OverviewTab({ detail }: { detail: EndpointDetail }) {
  const hostname = detail.identity?.hostname || detail.connection_status?.hostname || '—'
  const osName = detail.system?.os_name || '—'
  const osVer = detail.system?.os_version ? `Build ${detail.system.os_build || detail.system.os_version}` : ''
  const osArch = detail.system?.os_architecture || ''
  const cpu = detail.system?.cpu?.[0]
  const mem = detail.system?.memory
  const disks = detail.system?.disks || []
  const users = detail.users || []

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* System Information */}
      <Card title="System Information" subtitle="Hardware & operating system">
        <div className="divide-y divide-gray-100">
          <InfoRow label="Hostname" value={hostname} />
          <InfoRow label="Device UUID" value={detail.identity?.device_uuid} />
          <InfoRow label="Operating System" value={osName !== '—' ? `${osName} ${osVer}` : undefined} />
          <InfoRow label="OS Manufacturer" value={detail.system?.os_manufacturer} />
          <InfoRow label="Architecture" value={osArch} />
          <InfoRow label="CPU" value={cpu?.name} />
          <InfoRow label="CPU Cores / Threads" value={cpu ? `${cpu.cores} / ${cpu.logical_processors}` : undefined} />
          <InfoRow label="Max Clock" value={cpu?.max_clock_speed} />
          <InfoRow label="CPU Usage" value={detail.system?.cpu_usage_percent !== undefined ? `${detail.system.cpu_usage_percent}%` : undefined} />
          <InfoRow label="RAM Total" value={mem ? `${mem.total_gb} GB` : undefined} />
          <InfoRow label="RAM Used" value={mem ? `${mem.used_gb?.toFixed(1)} GB (${mem.percent_used}%)` : undefined} />
          <InfoRow label="Public IP" value={detail.network?.public_ip} />
          <InfoRow label="Uptime" value={detail.identity?.uptime} />
          <InfoRow label="Last Boot" value={detail.identity?.last_boot_time} />
          <InfoRow label="Agent Version" value={detail.agent_version} />
          <InfoRow label="First Seen" value={formatWhen(detail.first_seen)} />
          <InfoRow label="Last Updated" value={formatWhen(detail.last_updated)} />
          <InfoRow label="Collection Time" value={detail.collection_timestamp} />
        </div>
      </Card>

      {/* Storage */}
      <Card title="Storage" subtitle="Disk partitions & hardware">
        <div className="space-y-3">
          {disks.map((d, i) => {
            const pct = d.percent_used ?? 0
            const barColor = pct > 90 ? 'bg-red-500' : pct > 75 ? 'bg-amber-500' : 'bg-emerald-500'
            return (
              <div key={i} className="rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-gray-900">{d.mountpoint || d.device}</span>
                  <span className="text-xs text-gray-500">{d.filesystem}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-gray-200">
                  <div className={`h-2 rounded-full ${barColor} transition-all`} style={{ width: `${Math.min(pct, 100)}%` }} />
                </div>
                <div className="mt-1.5 flex items-center justify-between text-xs text-gray-500">
                  <span>{d.used_gb?.toFixed(1)} GB used</span>
                  <span>{d.free_gb?.toFixed(1)} GB free / {d.total_gb?.toFixed(1)} GB total</span>
                </div>
              </div>
            )
          })}
          {(detail.system?.storage || []).length > 0 && (
            <>
              <SectionTitle>Physical drives</SectionTitle>
              {(detail.system?.storage || []).map((s, i) => (
                <div key={i} className="rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-gray-900">{s.model}</span>
                    <span className="text-xs text-gray-500">{s.size_gib} GiB</span>
                  </div>
                  {s.serial && <p className="mt-0.5 font-mono text-xs text-gray-400">S/N: {s.serial}</p>}
                  {s.partitions && s.partitions.length > 0 && (
                    <p className="mt-1 text-xs text-gray-500">{s.partitions.join(' · ')}</p>
                  )}
                </div>
              ))}
            </>
          )}
          {disks.length === 0 && (detail.system?.storage || []).length === 0 && (
            <p className="py-4 text-center text-sm text-gray-400">No storage data available</p>
          )}
        </div>
      </Card>

      {/* User Accounts */}
      <Card title="User Accounts" subtitle={`${users.length} local user${users.length !== 1 ? 's' : ''}`} noPadding>
        {users.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>User</Th><Th>Status</Th><Th>Password</Th><Th>SID</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {users.map((u, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-2.5 font-medium text-gray-900">{u.name}{u.full_name ? ` (${u.full_name})` : ''}</td>
                    <td className="whitespace-nowrap px-5 py-2.5">
                      <div className="flex gap-1.5">
                        <Badge label={u.disabled ? 'Disabled' : 'Active'} tone={u.disabled ? 'neutral' : 'success'} size="sm" />
                        {u.lockout && <Badge label="Locked" tone="danger" size="sm" />}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-2.5 text-xs text-gray-500">
                      {u.password_required ? 'Required' : 'Not required'}{u.password_expires ? ' · Expires' : ''}
                    </td>
                    <td className="whitespace-nowrap px-5 py-2.5 font-mono text-[11px] text-gray-400">{u.sid || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="px-5 py-6 text-center text-sm text-gray-400">No user data</div>
        )}
      </Card>

      {/* USB History */}
      {(detail.usb_history || []).length > 0 && (
        <Card title="USB History" subtitle="Connected USB devices" noPadding>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Device</Th><Th>Instance</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {(detail.usb_history || []).map((u, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="px-5 py-2.5 text-gray-900">{u.device || '—'}</td>
                    <td className="px-5 py-2.5 font-mono text-xs text-gray-400">{u.instance || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}

function SecurityTab({ detail }: { detail: EndpointDetail }) {
  const antivirus = detail.security?.antivirus || []
  const firewallProducts = detail.security?.firewall || []
  const winFirewall = detail.security?.windows_firewall
  const bitlocker = detail.security?.bitlocker || []
  const defender = detail.security?.windows_defender

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* Antivirus */}
      <Card title="Antivirus" subtitle="Endpoint protection products">
        {antivirus.length > 0 ? (
          <div className="space-y-2">
            {antivirus.map((av, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-3">
                <span className="text-sm font-medium text-gray-900">{av.name}</span>
                <div className="flex gap-1.5">
                  <Badge label={av.enabled ? 'Enabled' : 'Disabled'} tone={av.enabled ? 'success' : 'danger'} size="sm" />
                  <Badge label={av.updated ? 'Updated' : 'Outdated'} tone={av.updated ? 'success' : 'warning'} size="sm" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="py-4 text-center text-sm text-gray-400">No antivirus data</p>
        )}
      </Card>

      {/* Firewall */}
      <Card title="Firewall" subtitle="Firewall profiles & products">
        <div className="space-y-4">
          {winFirewall && Object.keys(winFirewall).length > 0 && (
            <div>
              <SectionTitle>Windows Firewall Profiles</SectionTitle>
              <div className="flex flex-wrap gap-2">
                {Object.entries(winFirewall).map(([profile, state]) => (
                  <div key={profile} className="flex items-center gap-2 rounded-lg border border-gray-100 bg-gray-50/50 px-3 py-2">
                    <span className="text-xs font-medium text-gray-600">{profile}</span>
                    <Badge label={state} tone={state === 'ON' ? 'success' : 'danger'} size="sm" />
                  </div>
                ))}
              </div>
            </div>
          )}
          {firewallProducts.length > 0 && (
            <div>
              <SectionTitle>Third-party Firewalls</SectionTitle>
              <div className="space-y-2">
                {firewallProducts.map((fw, i) => (
                  <div key={i} className="flex items-center justify-between rounded-lg border border-gray-100 bg-gray-50/50 px-3 py-2">
                    <span className="text-sm font-medium text-gray-900">{fw.name}</span>
                    <Badge label={fw.enabled ? 'Enabled' : 'Disabled'} tone={fw.enabled ? 'success' : 'danger'} size="sm" />
                  </div>
                ))}
              </div>
            </div>
          )}
          {!winFirewall && firewallProducts.length === 0 && (
            <p className="py-4 text-center text-sm text-gray-400">No firewall data</p>
          )}
        </div>
      </Card>

      {/* Windows Defender */}
      {defender && (
        <Card title="Windows Defender" subtitle="Built-in protection status">
          <div className="divide-y divide-gray-100">
            <InfoRow label="Antivirus Enabled" value={defender.antivirus_enabled} />
            <InfoRow label="Realtime Protection" value={defender.realtime_protection} />
            <InfoRow label="Anti-spyware Enabled" value={defender.antispyware_enabled} />
            <InfoRow label="Signature Updated" value={defender.signature_updated || '—'} />
          </div>
        </Card>
      )}

      {/* BitLocker */}
      {bitlocker.length > 0 && (
        <Card title="BitLocker" subtitle="Drive encryption status">
          <div className="space-y-2">
            {bitlocker.map((bl, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-3">
                <span className="text-sm font-semibold text-gray-900">{bl.drive}</span>
                <Badge
                  label={bl.protection_status === 1 ? 'Protected' : 'Not Protected'}
                  tone={bl.protection_status === 1 ? 'success' : 'warning'}
                  size="sm"
                />
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Policies */}
      <Card title="System Policies" subtitle="UAC & update status">
        <div className="divide-y divide-gray-100">
          <InfoRow label="UAC Enabled" value={detail.security?.uac_enabled} />
          <InfoRow label="Pending Updates" value={detail.windows_updates?.pending_updates} />
          <InfoRow label="Last Boot" value={detail.windows_updates?.last_boot} />
        </div>
      </Card>
    </div>
  )
}

function NetworkTab({ detail }: { detail: EndpointDetail }) {
  const interfaces = detail.network?.interfaces || []
  const dns = detail.network?.dns_servers || []
  const conns = detail.network?.active_connections || []
  const ports = detail.network?.listening_ports || []

  return (
    <div className="space-y-4">
      {/* Summary row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Interfaces" subtitle="Network adapters">
          {interfaces.length > 0 ? (
            <div className="space-y-2">
              {interfaces.map((ifc, i) => (
                <div key={i} className="rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-3">
                  <div className="text-sm font-medium text-gray-900">{ifc.name}</div>
                  <div className="mt-1 flex flex-wrap gap-x-4 text-xs text-gray-500">
                    {ifc.ipv4 && <span>IPv4: <span className="font-mono text-gray-700">{ifc.ipv4}</span></span>}
                    {ifc.mac && <span>MAC: <span className="font-mono text-gray-700">{ifc.mac}</span></span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-4 text-center text-sm text-gray-400">No interface data</p>
          )}
        </Card>

        <Card title="DNS Servers">
          {dns.length > 0 ? (
            <div className="space-y-1.5">
              {dns.map((d, i) => (
                <div key={i} className="rounded-lg border border-gray-100 bg-gray-50/50 px-4 py-2.5 font-mono text-sm text-gray-900">{d}</div>
              ))}
            </div>
          ) : (
            <p className="py-4 text-center text-sm text-gray-400">No DNS data</p>
          )}
        </Card>

        <Card title="Public IP">
          <div className="flex flex-col items-center py-2">
            <span className="font-mono text-xl font-bold text-gray-900">{detail.network?.public_ip || '—'}</span>
          </div>
        </Card>
      </div>

      {/* Active Connections */}
      <Card title="Active Connections" subtitle={`${conns.length} connection${conns.length !== 1 ? 's' : ''}`} noPadding>
        {conns.length > 0 ? (
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Process</Th><Th>Local Address</Th><Th>Remote Address</Th><Th>Status</Th><Th>PID</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {conns.map((c, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-2 font-medium text-gray-900">{c.process || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 font-mono text-xs text-gray-600">{c.local_address || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 font-mono text-xs text-gray-600">{c.remote_address || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2">
                      <Badge label={c.status || '—'} tone={c.status === 'ESTABLISHED' ? 'success' : c.status === 'NONE' ? 'neutral' : 'info'} size="sm" />
                    </td>
                    <td className="whitespace-nowrap px-5 py-2 font-mono text-xs text-gray-400">{c.pid ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No active connections</p>
        )}
      </Card>

      {/* Listening Ports */}
      <Card title="Listening Ports" subtitle={`${ports.length} port${ports.length !== 1 ? 's' : ''}`} noPadding>
        {ports.length > 0 ? (
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Port</Th><Th>Protocol</Th><Th>Process</Th><Th>PID</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {ports.map((p, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-2 font-mono font-semibold text-gray-900">{p.port ?? '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 text-xs text-gray-600">{p.protocol || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 text-gray-700">{p.process || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 font-mono text-xs text-gray-400">{p.pid ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No listening ports data</p>
        )}
      </Card>
    </div>
  )
}

function SoftwareTab({ detail }: { detail: EndpointDetail }) {
  const apps = detail.applications || []
  const startup = detail.startup_programs || []

  return (
    <div className="space-y-4">
      {/* Installed Applications */}
      <Card title="Installed Applications" subtitle={`${apps.length} application${apps.length !== 1 ? 's' : ''} reported by agent`} noPadding>
        {apps.length > 0 ? (
          <div className="overflow-x-auto max-h-[32rem] overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Application</Th><Th>Version</Th><Th>Publisher</Th><Th>Install Location</Th><Th>Installed</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {apps.map((a, i) => (
                  <tr key={i} className="transition-colors hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-2.5 font-medium text-gray-900">{a.name || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2.5 font-mono text-xs text-gray-500">{a.version || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2.5 text-gray-500">{a.publisher || '—'}</td>
                    <td className="px-5 py-2.5 font-mono text-xs text-gray-400 max-w-xs truncate" title={a.install_location || ''}>{a.install_location || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2.5 text-gray-500">{a.install_date || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-8 text-center text-sm text-gray-400">No application data</p>
        )}
      </Card>

      {/* Startup Programs */}
      <Card title="Startup Programs" subtitle={`${startup.length} auto-start item${startup.length !== 1 ? 's' : ''}`} noPadding>
        {startup.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Name</Th><Th>Command</Th><Th>Location</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {startup.map((s, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-2.5 font-medium text-gray-900">{s.name || '—'}</td>
                    <td className="px-5 py-2.5 font-mono text-xs text-gray-500 max-w-md truncate" title={s.command || ''}>{s.command || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2.5 text-xs text-gray-500">{s.location || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No startup program data</p>
        )}
      </Card>
    </div>
  )
}

function ActivityTab({ detail }: { detail: EndpointDetail }) {
  const processes = detail.processes || []
  const tasks = detail.scheduled_tasks || []
  const prefetch = detail.prefetch_files || []

  return (
    <div className="space-y-4">
      {/* Processes */}
      <Card title="Running Processes" subtitle={`${processes.length} process${processes.length !== 1 ? 'es' : ''}`} noPadding>
        {processes.length > 0 ? (
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>PID</Th><Th>Process</Th><Th>User</Th><Th>Status</Th><Th className="text-right">Memory %</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {processes.map((p, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="whitespace-nowrap px-5 py-1.5 font-mono text-xs text-gray-500">{p.pid ?? '—'}</td>
                    <td className="whitespace-nowrap px-5 py-1.5 font-medium text-gray-900">{p.name || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-1.5 text-xs text-gray-500">{p.user || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-1.5">
                      <Badge label={p.status || '—'} tone={p.status === 'running' ? 'success' : 'neutral'} size="sm" />
                    </td>
                    <td className="whitespace-nowrap px-5 py-1.5 text-right font-mono text-xs text-gray-500">{typeof p.memory_percent === 'number' ? `${p.memory_percent.toFixed(1)}%` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No process data</p>
        )}
      </Card>

      {/* Scheduled Tasks */}
      <Card title="Scheduled Tasks" subtitle={`${tasks.length} task${tasks.length !== 1 ? 's' : ''}`} noPadding>
        {tasks.length > 0 ? (
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Task Name</Th><Th>Next Run / Status</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {tasks.map((t, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="px-5 py-2 font-medium text-gray-900">{t.name || '—'}</td>
                    <td className="px-5 py-2 text-xs text-gray-500">{t.status || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No scheduled task data</p>
        )}
      </Card>

      {/* Prefetch Files */}
      <Card title="Prefetch Files" subtitle={`${prefetch.length} file${prefetch.length !== 1 ? 's' : ''} — recent program executions`} noPadding>
        {prefetch.length > 0 ? (
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 bg-white z-10"><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>Filename</Th><Th>Size</Th><Th>Modified</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {prefetch.map((pf, i) => (
                  <tr key={i} className="hover:bg-gray-50/70">
                    <td className="px-5 py-2 font-mono text-xs text-gray-900">{pf.filename || '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 text-xs text-gray-500">{typeof pf.size_kb === 'number' ? `${pf.size_kb.toFixed(1)} KB` : '—'}</td>
                    <td className="whitespace-nowrap px-5 py-2 text-xs text-gray-500">{pf.modified || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-sm text-gray-400">No prefetch data</p>
        )}
      </Card>
    </div>
  )
}

function ScanTab({ results, onScan, endpointId }: { results: EndpointResults | null; onScan: () => void; endpointId: string }) {
  const es = (results?.endpoint_summary || {}) as any
  const [expandedApp, setExpandedApp] = useState<string | null>(null)
  const [appCves, setAppCves] = useState<ApplicationCves | null>(null)
  const [cvesLoading, setCvesLoading] = useState(false)
  const [cvesError, setCvesError] = useState<string | null>(null)

  async function toggleApp(productName: string) {
    if (expandedApp === productName) {
      setExpandedApp(null)
      setAppCves(null)
      return
    }
    setExpandedApp(productName)
    setAppCves(null)
    setCvesError(null)
    setCvesLoading(true)
    try {
      const data = await api.getApplicationCves(endpointId, productName)
      setAppCves(data)
    } catch (e: any) {
      setCvesError(e?.message || 'Failed to load CVEs')
    } finally {
      setCvesLoading(false)
    }
  }

  if (results?.scan_status === 'not_scanned') {
    return (
      <Card>
        <div className="flex flex-col items-center py-8 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-gray-100 mb-4">
            <svg className="h-7 w-7 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <p className="text-sm font-medium text-gray-900">No scan results yet</p>
          <p className="mt-1 text-xs text-gray-500">Run a vulnerability scan to see risk analysis for this endpoint.</p>
          <Button onClick={onScan} variant="primary" size="sm" className="mt-4">Run scan</Button>
        </div>
      </Card>
    )
  }

  if (results?.scan_status !== 'completed') {
    return (
      <Card>
        <p className="py-8 text-center text-sm text-gray-400">
          {results?.scan_status === 'failed' ? 'Last scan failed. Try running a new scan.' : 'Waiting for scan to complete…'}
        </p>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Risk summary */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-1">
          <div className="flex flex-col items-center text-center">
            <p className="text-[11px] font-medium uppercase tracking-wider text-gray-500">Overall risk</p>
            <div className={`mt-2 text-4xl font-bold tabular-nums animate-score-appear ${riskColor(es.endpoint_risk_tier)}`}>
              {typeof es.endpoint_risk_score_0_100 === 'number' ? Number(es.endpoint_risk_score_0_100).toFixed(1) : '—'}
            </div>
            <p className="text-xs text-gray-400">/100</p>
            <div className="mt-3"><RiskPill tier={es.endpoint_risk_tier} size="md" /></div>
            <p className="mt-3 text-[11px] text-gray-400">Last scanned: {formatWhen(results?.last_scanned_at)}</p>
          </div>
        </Card>
        <div className="grid grid-cols-2 gap-3 lg:col-span-3">
          <StatBox label="Vulnerable apps" value={es.application_count_with_cves ?? '—'} />
          <StatBox label="Total CVEs" value={es.total_cve_count ?? '—'} color="text-gray-900" />
          <StatBox label="KEV (Known Exploited)" value={es.total_kev_count ?? '—'} color={Number(es.total_kev_count) > 0 ? 'text-amber-600' : undefined} />
          <StatBox label="Exploit evidence" value={es.total_exploit_evidence_count ?? '—'} color={Number(es.total_exploit_evidence_count) > 0 ? 'text-red-600' : undefined} />
          <StatBox label="Combined risk" value={typeof es.endpoint_combined_risk_0_100 === 'number' ? `${Number(es.endpoint_combined_risk_0_100).toFixed(1)}/100` : '—'} />
          <StatBox label="Worst app risk" value={typeof es.max_application_risk_0_100 === 'number' ? `${Number(es.max_application_risk_0_100).toFixed(1)}/100` : '—'} />
        </div>
      </div>

      {/* Vulnerability risk table */}
      {(results?.application_summaries?.length || 0) > 0 && (
        <Card title="Vulnerability Risk Breakdown" subtitle="Click an application to view its CVEs" noPadding>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-gray-100 bg-gray-50/60">
                <Th>&nbsp;</Th><Th>Application</Th><Th>Version</Th><Th className="text-center">CVEs</Th><Th>Risk</Th><Th>Signals</Th>
              </tr></thead>
              <tbody className="divide-y divide-gray-100">
                {(results?.application_summaries || []).map((a) => {
                  const appKey = a.display_product
                  const isExpanded = expandedApp === appKey
                  return (
                    <React.Fragment key={`${a.display_product}:${a.version_normalized || ''}`}>
                      <tr
                        className={`transition-colors cursor-pointer ${isExpanded ? 'bg-indigo-50/60' : 'hover:bg-gray-50/70'}`}
                        onClick={() => void toggleApp(appKey)}
                      >
                        <td className="whitespace-nowrap pl-5 pr-1 py-3 text-gray-400">
                          <svg className={`h-4 w-4 transition-transform ${isExpanded ? 'rotate-90' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                        <td className="whitespace-nowrap px-5 py-3 font-medium text-gray-900">{a.display_product}</td>
                        <td className="whitespace-nowrap px-5 py-3 font-mono text-xs text-gray-500">{a.version_normalized || '—'}</td>
                        <td className="whitespace-nowrap px-5 py-3 text-center tabular-nums text-gray-600">{a.matched_cve_count}</td>
                        <td className="whitespace-nowrap px-5 py-3">
                          <div className="flex items-center gap-2.5">
                            <span className={`font-semibold tabular-nums ${riskColor(a.application_risk_tier)}`}>
                              {typeof a.application_risk_score_0_100 === 'number' ? `${a.application_risk_score_0_100.toFixed(1)}` : '—'}
                            </span>
                            <span className="text-[11px] text-gray-400">/100</span>
                            <RiskPill tier={a.application_risk_tier} />
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-5 py-3">
                          <div className="flex flex-wrap gap-1.5">
                            {a.kev_cve_count > 0 && <Badge label={`KEV ${a.kev_cve_count}`} tone="warning" />}
                            {a.exploit_evidence_count > 0 && <Badge label={`Exploit ${a.exploit_evidence_count}`} tone="danger" />}
                            {a.kev_cve_count === 0 && a.exploit_evidence_count === 0 && <span className="text-xs text-gray-400">None</span>}
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="p-0">
                            <CvePanel loading={cvesLoading} error={cvesError} data={appCves} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}

/* ── CVE expanded panel ── */
function severityTone(s?: string): 'danger' | 'warning' | 'info' | 'success' | 'neutral' {
  if (!s) return 'neutral'
  const lower = s.toLowerCase()
  if (lower === 'critical') return 'danger'
  if (lower === 'high') return 'danger'
  if (lower === 'medium') return 'warning'
  if (lower === 'low') return 'info'
  return 'neutral'
}

function CvePanel({ loading, error, data }: { loading: boolean; error: string | null; data: ApplicationCves | null }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-6 bg-gray-50/50">
        <Spinner /><span className="ml-2 text-sm text-gray-500">Loading CVEs…</span>
      </div>
    )
  }
  if (error) {
    return (
      <div className="px-8 py-4 bg-red-50/50 text-sm text-red-600">{error}</div>
    )
  }
  if (!data || data.matched_cves.length === 0) {
    return (
      <div className="px-8 py-4 bg-gray-50/50 text-sm text-gray-400">No CVEs matched for this application.</div>
    )
  }
  return (
    <div className="bg-gray-50/80 border-t border-gray-200">
      <div className="px-8 py-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
        {data.matched_cve_count} CVE{data.matched_cve_count !== 1 ? 's' : ''} for {data.display_product}
      </div>
      <div className="space-y-2 px-8 pb-4">
        {data.matched_cves.map((cve) => (
          <CveRow key={cve.cve_id} cve={cve} />
        ))}
      </div>
    </div>
  )
}

function CveRow({ cve }: { cve: CveDetail }) {
  const severity = cve.cvss_v3?.baseSeverity || cve.risk_tier || '—'
  const score = cve.cvss_v3?.baseScore
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`

  return (
    <a
      href={nvdUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center justify-between gap-4 rounded-lg border border-gray-200 bg-white px-4 py-3 transition hover:bg-gray-50/70 hover:border-indigo-200"
    >
      <div className="flex items-center gap-3 min-w-0">
        <span className="font-mono text-sm font-semibold text-indigo-600 shrink-0">{cve.cve_id}</span>
        <Badge label={severity} tone={severityTone(severity)} size="sm" />
        {typeof score === 'number' && (
          <span className="text-xs font-medium text-gray-500">CVSS {score.toFixed(1)}</span>
        )}
        {cve.kev_flag && <Badge label="KEV" tone="warning" size="sm" />}
        {(cve.vulners_exploit_flag || cve.exploitdb_flag) && <Badge label="Exploit" tone="danger" size="sm" />}
      </div>
      <svg className="h-4 w-4 shrink-0 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
      </svg>
    </a>
  )
}

/* ═══════════════ MAIN PAGE ═══════════════ */

export function EndpointDetails() {
  const { endpointId } = useParams()
  const id = endpointId ? decodeURIComponent(endpointId) : ''

  const [results, setResults] = useState<EndpointResults | null>(null)
  const [detail, setDetail] = useState<EndpointDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [cancelling, setCancelling] = useState(false)
  const [activeTab, setActiveTab] = useState<TabKey>('overview')

  async function load() {
    if (!id) return
    setLoading(true)
    setError(null)
    try {
      const [res, det] = await Promise.all([api.getResults(id), api.getEndpoint(id)])
      setResults(res)
      setDetail(det)
    } catch (e: any) {
      setError(e?.message || 'Failed to load endpoint')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [id])

  useEffect(() => {
    if (!results || results.scan_status !== 'scanning') return
    const t = window.setInterval(() => void load(), 4000)
    return () => window.clearInterval(t)
  }, [results?.scan_status])

  // General auto-refresh every 60 seconds to pick up agent updates
  useEffect(() => {
    const t = window.setInterval(() => void load(), 60_000)
    return () => window.clearInterval(t)
  }, [id])

  async function onScan() {
    if (!id) return
    setScanError(null)
    // Optimistically show scanning immediately (Firestore writes + API merge can be slightly delayed).
    setResults((prev) => {
      if (!prev) {
        return {
          endpoint_id: id,
          scan_status: 'scanning',
          last_scanned_at: null,
          endpoint_summary: null,
          application_summaries: [],
          error_message: null,
        }
      }
      return { ...prev, scan_status: 'scanning', error_message: null }
    })
    try {
      await api.startScan(id)
      // Best-effort refresh; polling will keep updating while scan runs.
      void load()
    } catch (e: any) {
      setScanError(e?.message || 'Failed to start scan')
      // Roll back optimistic state on failure.
      setResults((prev) => (prev ? { ...prev, scan_status: 'failed' } : prev))
    }
  }

  async function onCancel() {
    if (!id) return
    setCancelling(true)
    try {
      await api.cancelScan(id)
      await load()
    } catch (e: any) {
      setScanError(e?.message || 'Failed to cancel scan')
    } finally {
      setCancelling(false)
    }
  }

  const isScanning = results?.scan_status === 'scanning'
  const hostname = detail?.identity?.hostname || detail?.connection_status?.hostname || '—'
  const osName = detail?.system?.os_name || '—'
  const osVer = detail?.system?.os_version ? `Build ${detail.system.os_build || detail.system.os_version}` : ''
  const osArch = detail?.system?.os_architecture || ''
  const isOnline = detail?.connection_status?.online

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      {/* Header */}
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <Link to="/" className="mb-3 inline-flex items-center gap-1.5 text-sm text-gray-500 transition hover:text-gray-900">
            <ArrowLeftIcon /> Back to dashboard
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-gray-900">{hostname}</h1>
            {isOnline !== undefined && (
              <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${isOnline ? 'bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-600/20' : 'bg-gray-100 text-gray-500 ring-1 ring-inset ring-gray-300'}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${isOnline ? 'bg-emerald-500' : 'bg-gray-400'}`} />
                {isOnline ? 'Online' : 'Offline'}
              </span>
            )}
          </div>
          <p className="mt-1 font-mono text-sm text-gray-400">{id}</p>
          {osName !== '—' && <p className="mt-0.5 text-sm text-gray-500">{osName} {osVer} {osArch}</p>}
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={() => void load()} variant="secondary" size="sm" icon={<RefreshIcon />}>Refresh</Button>
          {!isScanning && <Button onClick={() => void onScan()} variant="primary" size="sm">Run scan</Button>}
        </div>
      </div>

      {/* Error banners */}
      {scanError && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <span className="mt-0.5 shrink-0">⚠</span><span>{scanError}</span>
        </div>
      )}
      {error && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <span className="mt-0.5 shrink-0">⚠</span><span>{error}</span>
        </div>
      )}

      {/* Scan progress banner */}
      {isScanning && <ScanProgressBanner onCancel={onCancel} cancelling={cancelling} />}

      {/* Failed banner */}
      {results?.scan_status === 'failed' && results.error_message && (
        <div className="mb-6 rounded-lg border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-800">
          <p className="font-semibold">Scan failed</p>
          <p className="mt-1 whitespace-pre-wrap break-words text-xs text-red-700">{results.error_message}</p>
        </div>
      )}

      {/* Tab navigation */}
      <div className="mb-6 border-b border-gray-200">
        <nav className="-mb-px flex gap-1 overflow-x-auto" aria-label="Tabs">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`whitespace-nowrap border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                activeTab === tab.key
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      {loading && !detail ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : detail ? (
        <>
          {activeTab === 'overview' && <OverviewTab detail={detail} />}
          {activeTab === 'security' && <SecurityTab detail={detail} />}
          {activeTab === 'network' && <NetworkTab detail={detail} />}
          {activeTab === 'software' && <SoftwareTab detail={detail} />}
          {activeTab === 'activity' && <ActivityTab detail={detail} />}
          {activeTab === 'scan' && <ScanTab results={results} onScan={onScan} endpointId={id} />}
        </>
      ) : null}
    </div>
  )
}
