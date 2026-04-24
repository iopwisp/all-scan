function normalizeBaseUrl(value) {
  return String(value ?? '')
    .trim()
    .replace(/\/$/, '')
    .replace(/\/api$/, '')
}

function isLocalHostname(hostname) {
  return ['localhost', '127.0.0.1', '::1'].includes(hostname)
}

function getApiCandidates() {
  const configuredBase = normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL)
  const configuredProxy = normalizeBaseUrl(import.meta.env.VITE_API_PROXY_TARGET)
  const candidates = [configuredBase, configuredProxy, '']

  if (typeof window !== 'undefined' && isLocalHostname(window.location.hostname)) {
    candidates.push(
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:8000',
      'http://127.0.0.1:8000',
    )
  }

  return [...new Set(candidates.filter((value, index) => value || index === 0))]
}

function buildUrl(baseUrl, path) {
  return `${baseUrl}${path}`
}

function shouldTryAnotherApi(error, method = 'GET') {
  if (error?.name === 'TypeError') {
    return true
  }

  if (typeof error?.status !== 'number') {
    return true
  }

  if (method !== 'GET') {
    return error.status === 502 || error.status === 503 || error.status === 504
  }

  return error.status === 404 || error.status === 405 || error.status >= 500
}

const defaultHeaders = {
  Accept: 'application/json',
}

let activeApiBase = null
let discoveryPromise = null

async function performRequest(url, options = {}) {
  const headers = {
    ...defaultHeaders,
    ...(options.headers ?? {}),
  }

  const init = {
    ...options,
    headers,
  }

  if (init.body && typeof init.body !== 'string' && !(init.body instanceof FormData)) {
    init.body = JSON.stringify(init.body)
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(url, init)
  const contentType = response.headers.get('content-type') ?? ''

  let payload

  if (contentType.includes('application/json')) {
    payload = await response.json()
  } else if (contentType.includes('application/pdf') || contentType.includes('application/octet-stream')) {
    payload = await response.blob()
  } else {
    payload = await response.text()
  }

  if (!response.ok) {
    const message =
      typeof payload === 'string'
        ? payload || `Request failed with status ${response.status}`
        : payload?.message || `Request failed with status ${response.status}`

    const error = new Error(message)
    error.status = response.status
    error.payload = payload
    throw error
  }

  return payload
}

async function discoverApiBase(force = false) {
  if (!force && activeApiBase !== null) {
    return activeApiBase
  }

  if (!force && discoveryPromise) {
    return discoveryPromise
  }

  discoveryPromise = (async () => {
    let lastError = null

    for (const candidate of getApiCandidates()) {
      try {
        await performRequest(buildUrl(candidate, '/api/scans'))
        activeApiBase = candidate
        return candidate
      } catch (error) {
        lastError = error
        if (!shouldTryAnotherApi(error)) {
          throw error
        }
      }
    }

    throw lastError ?? new Error('API unavailable')
  })()

  try {
    return await discoveryPromise
  } finally {
    discoveryPromise = null
  }
}

async function request(path, options = {}) {
  const method = String(options.method ?? 'GET').toUpperCase()
  const baseUrl = activeApiBase ?? (await discoverApiBase())

  try {
    return await performRequest(buildUrl(baseUrl, path), options)
  } catch (error) {
    if (!shouldTryAnotherApi(error, method)) {
      throw error
    }

    activeApiBase = null
    const fallbackBaseUrl = await discoverApiBase(true)

    if (fallbackBaseUrl === baseUrl) {
      throw error
    }

    return performRequest(buildUrl(fallbackBaseUrl, path), options)
  }
}

export function createScan(body) {
  return request('/api/scans', {
    method: 'POST',
    body,
  })
}

export function getScans() {
  return request('/api/scans')
}

export function getScan(id) {
  return request(`/api/scans/${id}`)
}

export function getScanStatus(id) {
  return request(`/api/scans/${id}/status`)
}

export function getScanResults(id) {
  return request(`/api/scans/${id}/results`)
}

export function getScanReport(id) {
  return request(`/api/scans/${id}/report`)
}

export function downloadScanReportPdf(id) {
  return request(`/api/scans/${id}/report`, {
    headers: {
      Accept: 'application/pdf',
    },
  })
}
