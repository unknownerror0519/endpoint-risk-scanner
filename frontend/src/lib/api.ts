import type { EndpointListItem, EndpointResults, EndpointDetail, ApplicationCves } from '../types'

const baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8000'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  })

  if (!res.ok) {
    let body: any = null
    try {
      body = await res.json()
    } catch {
      body = await res.text()
    }

    // FastAPI typically returns { detail: ... }
    const detail = typeof body === 'object' && body ? (body as any).detail : body
    if (typeof detail === 'string') throw new Error(detail)
    if (typeof detail === 'object' && detail) {
      const message = (detail as any).message
      if (typeof message === 'string' && message.trim()) throw new Error(message)
    }
    throw new Error(typeof body === 'string' ? body : JSON.stringify(body))
  }

  return (await res.json()) as T
}

export const api = {
  listEndpoints: (limit = 200) => request<EndpointListItem[]>(`/endpoints?limit=${limit}`),
  getEndpoint: (endpointId: string) => request<EndpointDetail>(`/endpoints/${encodeURIComponent(endpointId)}`),
  getResults: (endpointId: string) => request<EndpointResults>(`/endpoints/${encodeURIComponent(endpointId)}/results`),
  startScan: (endpointId: string) => request<{ endpoint_id: string; scan_status: string }>(`/endpoints/${encodeURIComponent(endpointId)}/scan`, { method: 'POST' }),
  cancelScan: (endpointId: string) => request<{ endpoint_id: string; cancelled: boolean; message: string }>(`/endpoints/${encodeURIComponent(endpointId)}/cancel`, { method: 'POST' }),
  getApplicationCves: (endpointId: string, productName: string) =>
    request<ApplicationCves>(`/endpoints/${encodeURIComponent(endpointId)}/cves/${encodeURIComponent(productName)}`),
}
