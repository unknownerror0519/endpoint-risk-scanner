import clsx from 'clsx'
import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: ReactNode
}

export function Button({ className, variant = 'secondary', size = 'md', icon, children, ...props }: Props) {
  const base =
    'inline-flex items-center justify-center gap-1.5 font-medium transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:opacity-40 disabled:cursor-not-allowed'

  const sizes =
    size === 'sm'
      ? 'rounded-md px-2.5 py-1.5 text-xs'
      : 'rounded-lg px-3.5 py-2 text-sm'

  const styles =
    variant === 'primary'
      ? 'bg-indigo-600 text-white shadow-sm hover:bg-indigo-500 focus-visible:ring-indigo-500'
      : variant === 'danger'
        ? 'bg-red-600 text-white shadow-sm hover:bg-red-500 focus-visible:ring-red-500'
        : variant === 'ghost'
          ? 'bg-transparent text-gray-600 hover:bg-gray-100 hover:text-gray-900 focus-visible:ring-gray-400'
          : 'bg-white text-gray-700 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus-visible:ring-indigo-500'

  return (
    <button className={clsx(base, sizes, styles, className)} {...props}>
      {icon}
      {children}
    </button>
  )
}
