import clsx from 'clsx'

type Props = {
  label: string
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info'
  size?: 'sm' | 'md'
}

export function Badge({ label, tone = 'neutral', size = 'sm' }: Props) {
  const className = clsx(
    'inline-flex items-center font-medium ring-1 ring-inset',
    size === 'sm' && 'rounded-md px-2 py-0.5 text-[11px] leading-5',
    size === 'md' && 'rounded-lg px-2.5 py-1 text-xs',
    tone === 'neutral' && 'bg-gray-50 text-gray-600 ring-gray-200 dark:bg-slate-700/40 dark:text-slate-200 dark:ring-slate-600/60',
    tone === 'success' && 'bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/20',
    tone === 'warning' && 'bg-amber-50 text-amber-700 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-400/20',
    tone === 'danger' && 'bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/20',
    tone === 'info' && 'bg-blue-50 text-blue-700 ring-blue-600/20 dark:bg-blue-500/10 dark:text-blue-300 dark:ring-blue-400/20'
  )

  return <span className={className}>{label}</span>
}
