import { Badge } from './Badge'

export function riskTone(tier?: string | null): 'neutral' | 'success' | 'warning' | 'danger' {
  const t = (tier || '').toUpperCase()
  if (t === 'LOW') return 'success'
  if (t === 'MODERATE') return 'warning'
  if (t === 'HIGH' || t === 'SEVERE' || t === 'CRITICAL') return 'danger'
  return 'neutral'
}

export function riskColor(tier?: string | null): string {
  const t = (tier || '').toUpperCase()
  if (t === 'LOW') return 'text-emerald-600 dark:text-emerald-400'
  if (t === 'MODERATE') return 'text-amber-600 dark:text-amber-400'
  if (t === 'HIGH' || t === 'SEVERE' || t === 'CRITICAL') return 'text-red-600 dark:text-red-400'
  return 'text-gray-400 dark:text-slate-400'
}

export function RiskPill({ tier, size }: { tier?: string | null; size?: 'sm' | 'md' }) {
  if (!tier) return <Badge label="—" tone="neutral" size={size} />
  return <Badge label={tier.toUpperCase()} tone={riskTone(tier)} size={size} />
}
