import { Link, useLocation } from 'react-router-dom'

const ShieldIcon = () => (
  <svg className="h-6 w-6 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
)

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const isHome = location.pathname === '/'

  return (
    <div className="flex min-h-full flex-col">
      <header className="sticky top-0 z-50 border-b border-gray-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <ShieldIcon />
            <span className="text-lg font-semibold tracking-tight text-gray-900 dark:text-slate-100">
              Endpoint Risk Scanner
            </span>
          </Link>
          <nav className="flex items-center gap-1">
            <Link
              to="/"
              className={`rounded-lg px-3 py-2 text-sm font-medium transition ${
                isHome
                  ? 'bg-gray-100 text-gray-900 dark:bg-slate-800 dark:text-slate-100'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100'
              }`}
            >
              Dashboard
            </Link>
          </nav>
        </div>
      </header>
      <main className="flex-1">{children}</main>
    </div>
  )
}
