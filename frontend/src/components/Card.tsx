import clsx from 'clsx'
import type { ReactNode } from 'react'

type Props = {
  title?: string
  subtitle?: string
  right?: ReactNode
  children: ReactNode
  className?: string
  noPadding?: boolean
}

export function Card({ title, subtitle, right, children, className, noPadding }: Props) {
  return (
    <div className={clsx(
      'overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm',
      className
    )}>
      {(title || subtitle || right) && (
        <div className="flex items-start justify-between gap-4 border-b border-gray-100 px-6 py-4">
          <div>
            {title && <h3 className="text-sm font-semibold text-gray-900">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-gray-500">{subtitle}</p>}
          </div>
          {right}
        </div>
      )}
      <div className={noPadding ? '' : 'px-6 py-5'}>
        {children}
      </div>
    </div>
  )
}
