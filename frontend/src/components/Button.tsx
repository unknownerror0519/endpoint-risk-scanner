import clsx from 'clsx'
import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: ReactNode
}

export function Button({ className, variant = 'secondary', size = 'md', icon, children, ...props }: Props) {
  const base =
    'inline-flex items-center justify-center gap-1.5 font-medium transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-slate-900 disabled:opacity-40 disabled:cursor-not-allowed'

  const sizes =
    size === 'sm'
      ? 'rounded-md px-2.5 py-1.5 text-xs'
      : 'rounded-lg px-3.5 py-2 text-sm'

  const styles =
    variant === 'primary'
      ? 'bg-indigo-600 text-white shadow-sm hover:bg-indigo-500 focus-visible:ring-indigo-500 dark:focus-visible:ring-indigo-400'
      : variant === 'danger'
        ? 'bg-red-600 text-white shadow-sm hover:bg-red-500 focus-visible:ring-red-500 dark:focus-visible:ring-red-400'
        : variant === 'ghost'
          ? 'bg-transparent text-gray-600 hover:bg-gray-100 hover:text-gray-900 focus-visible:ring-gray-400 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100 dark:focus-visible:ring-slate-500'
          : 'bg-white text-gray-700 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus-visible:ring-indigo-500 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-700 dark:focus-visible:ring-indigo-400'

  return (
    <button className={clsx(base, sizes, styles, className)} {...props}>
      {icon}
      {children}
    </button>
  )
}
