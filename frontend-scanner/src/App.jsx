import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  createScan,
  downloadScanReportPdf,
  getScan,
  getScanResults,
  getScans,
  getScanStatus,
} from './lib/api'
import {
  advantageCards,
  appPages,
  capabilityCards,
  demoReport,
  demoResults,
  demoScans,
  demoStatus,
  landingFeatures,
  progressStages,
  scanTypeOptions,
  supportedVulnerabilities,
  vulnerabilityChecks,
} from './lib/demo-data'

const severityOrder = ['Critical', 'High', 'Medium', 'Low']

const severityStyles = {
  Critical: 'border-rose-400/30 bg-rose-500/10 text-rose-100',
  High: 'border-orange-400/30 bg-orange-500/10 text-orange-100',
  Medium: 'border-amber-300/30 bg-amber-400/10 text-amber-100',
  Low: 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100',
}

const scanTypeApiMap = {
  fast: 'QUICK',
  deep: 'FULL',
  'owasp-full': 'FULL',
}

const checkTypeApiMap = {
  xss: 'XSS',
  sqli: 'SQLI',
  csrf: 'CSRF',
  directoryScan: 'OPEN_DIRECTORIES',
  configLeak: 'LEAKAGE',
}

function getPageFromHash() {
  const hash = window.location.hash.replace('#', '')
  return appPages.some((page) => page.id === hash) ? hash : 'landing'
}

function formatDateLabel(value) {
  if (!value) {
    return '—'
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function formatTimeLabel(value) {
  return new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value))
}

function prettifyStatus(value) {
  if (!value) {
    return 'Idle'
  }

  return String(value)
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function inferStage(percent) {
  const index = Math.min(
    progressStages.length - 1,
    Math.floor((Math.max(percent, 1) / 100) * progressStages.length),
  )

  return progressStages[index]
}

function inferSeverityCounts(findings) {
  return findings.reduce(
    (totals, finding) => {
      const key = finding.severity
      return {
        ...totals,
        [key]: (totals[key] ?? 0) + 1,
      }
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0 },
  )
}

function sortScans(list) {
  return [...list].sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt))
}

function normalizeScan(scan = {}) {
  const summary = scan.summary ?? scan.metrics ?? scan.resultsSummary ?? {}

  return {
    id: String(scan.id ?? scan.scanId ?? scan.uuid ?? ''),
    targetUrl: scan.targetUrl ?? scan.url ?? scan.target ?? scan.website ?? 'Unknown target',
    scanType: scan.scanType ?? scan.type ?? scan.profile ?? 'Deep',
    status: String(scan.status ?? scan.state ?? 'queued').toLowerCase(),
    riskScore: Number(summary.riskScore ?? scan.riskScore ?? scan.score ?? 0) || 0,
    critical: Number(summary.critical ?? scan.critical ?? 0) || 0,
    high: Number(summary.high ?? scan.high ?? 0) || 0,
    medium: Number(summary.medium ?? scan.medium ?? 0) || 0,
    low: Number(summary.low ?? scan.low ?? 0) || 0,
    createdAt: scan.createdAt ?? scan.startedAt ?? scan.created_at ?? new Date().toISOString(),
  }
}

function normalizeScans(payload) {
  const list = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.scans)
      ? payload.scans
      : Array.isArray(payload?.data)
        ? payload.data
        : []

  return list.map(normalizeScan).filter((scan) => scan.id)
}

function normalizeStatus(payload = {}, fallbackScan = {}) {
  const percent = Math.max(
    0,
    Math.min(100, Number(payload.percent ?? payload.progress ?? payload.percentage ?? 0) || 0),
  )
  const logsSource = Array.isArray(payload.logs)
    ? payload.logs
    : Array.isArray(payload.events)
      ? payload.events
      : []
  const logs = logsSource.map((entry, index) => ({
    time: entry.time ?? formatTimeLabel(entry.timestamp ?? Date.now() + index * 1000),
    level: String(entry.level ?? entry.type ?? 'info').toLowerCase(),
    message: entry.message ?? entry.text ?? `Log event ${index + 1}`,
  }))
  const rawStages = Array.isArray(payload.stages)
    ? payload.stages.map((stage) => (typeof stage === 'string' ? stage : stage.name ?? stage.title))
    : progressStages

  return {
    id: String(payload.id ?? payload.scanId ?? fallbackScan.id ?? ''),
    state: String(payload.state ?? payload.status ?? (percent >= 100 ? 'completed' : 'running')).toLowerCase(),
    percent,
    currentStage: payload.currentStage ?? payload.stage ?? inferStage(percent),
    stages: rawStages.length ? rawStages : progressStages,
    logs: logs.length ? logs : demoStatus.logs,
  }
}

function aggregateOwaspMappings(findings) {
  const map = findings.reduce((accumulator, finding) => {
    const label = finding.owasp || 'Unmapped'
    const existing = accumulator[label]

    if (existing) {
      existing.count += 1
      return accumulator
    }

    const [code, ...titleParts] = label.split(' ')

    return {
      ...accumulator,
      [label]: {
        code,
        title: titleParts.join(' ') || label,
        count: 1,
        description: 'Mapped automatically from the detected finding set.',
      },
    }
  }, {})

  return Object.values(map)
}

function normalizeResults(payload = {}, fallbackScan = {}) {
  const findingsSource = Array.isArray(payload.findings)
    ? payload.findings
    : Array.isArray(payload.vulnerabilities)
      ? payload.vulnerabilities
      : []

  const findings = findingsSource.map((finding, index) => ({
    type: finding.type ?? finding.name ?? `Finding ${index + 1}`,
    severity: finding.severity ?? 'Low',
    url: finding.url ?? finding.path ?? '/',
    parameter: finding.parameter ?? finding.param ?? '-',
    description: finding.description ?? finding.details ?? 'No description provided.',
    recommendation:
      finding.recommendation ?? finding.remediation ?? 'Review and patch the affected flow.',
    owasp: finding.owasp ?? finding.owaspCategory ?? 'Unmapped',
  }))
  const counts = inferSeverityCounts(findings)
  const summary = payload.summary ?? payload.metrics ?? payload.overview ?? {}
  const critical = Number(summary.critical ?? payload.critical ?? counts.Critical ?? 0) || 0
  const high = Number(summary.high ?? payload.high ?? counts.High ?? 0) || 0
  const medium = Number(summary.medium ?? payload.medium ?? counts.Medium ?? 0) || 0
  const low = Number(summary.low ?? payload.low ?? counts.Low ?? 0) || 0
  const riskScore = Number(summary.riskScore ?? payload.riskScore ?? payload.score ?? 0) || 0
  const owaspSource = Array.isArray(payload.owaspMappings)
    ? payload.owaspMappings
    : Array.isArray(payload.owasp)
      ? payload.owasp
      : []

  const owaspMappings = owaspSource.length
    ? owaspSource.map((item) => ({
        code: item.code ?? item.id ?? 'A00',
        title: item.title ?? item.name ?? 'Unmapped',
        count: Number(item.count ?? item.total ?? 0) || 0,
        description: item.description ?? 'OWASP category returned by the API.',
      }))
    : aggregateOwaspMappings(findings)

  return {
    id: String(payload.id ?? payload.scanId ?? fallbackScan.id ?? ''),
    targetUrl:
      payload.targetUrl ?? payload.url ?? fallbackScan.targetUrl ?? demoResults.targetUrl,
    scanType: payload.scanType ?? payload.type ?? fallbackScan.scanType ?? demoResults.scanType,
    summary: {
      riskScore,
      critical,
      high,
      medium,
      low,
    },
    findings: findings.length ? findings : demoResults.findings,
    owaspMappings: owaspMappings.length ? owaspMappings : demoResults.owaspMappings,
    severityChart: severityOrder.map((label) => ({
      label,
      value:
        label === 'Critical'
          ? critical
          : label === 'High'
            ? high
            : label === 'Medium'
              ? medium
              : low,
    })),
    trend: Array.isArray(payload.trend) && payload.trend.length ? payload.trend : demoResults.trend,
  }
}

function normalizeReport(payload = {}, fallbackScan = {}) {
  return {
    id: String(payload.id ?? payload.scanId ?? fallbackScan.id ?? demoReport.id),
    generatedAt:
      payload.generatedAt ?? payload.createdAt ?? payload.generated_at ?? new Date().toISOString(),
    format: payload.format ?? payload.type ?? demoReport.format,
    size: payload.size ?? payload.fileSize ?? demoReport.size,
    scope: payload.scope ?? demoReport.scope,
    summary: payload.summary ?? payload.description ?? demoReport.summary,
    artifacts:
      Array.isArray(payload.artifacts) && payload.artifacts.length
        ? payload.artifacts.map((item) => ({
            label: item.label ?? item.name ?? 'Artifact',
            detail: item.detail ?? item.description ?? 'Generated output.',
          }))
        : demoReport.artifacts,
  }
}

function buildDemoResults(scanId, targetUrl, scanType) {
  return {
    ...demoResults,
    id: scanId,
    targetUrl,
    scanType,
  }
}

function buildDemoReport(scanId, targetUrl, scanType) {
  return {
    ...demoReport,
    id: scanId,
    summary: `Demo report for ${targetUrl} (${scanType}) with PDF and JSON artifacts ready.`,
  }
}

function buildEmptyStatus() {
  return {
    id: '',
    state: 'idle',
    percent: 0,
    currentStage: 'Waiting for first scan',
    stages: progressStages,
    logs: [
      {
        time: formatTimeLabel(Date.now()),
        level: 'info',
        message: 'Live API connected. Start a scan to see progress here.',
      },
    ],
  }
}

function buildEmptyResults() {
  return {
    id: '',
    targetUrl: 'No scans yet',
    scanType: '—',
    summary: {
      riskScore: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    findings: [],
    owaspMappings: [],
    severityChart: severityOrder.map((label) => ({
      label,
      value: 0,
    })),
    trend: demoResults.trend.map((point) => ({
      ...point,
      value: 0,
    })),
  }
}

function buildEmptyReport() {
  return {
    id: '',
    generatedAt: new Date().toISOString(),
    format: 'Pending',
    size: 'Pending',
    scope: 'No active scan',
    summary: 'Start a scan to generate a report.',
    artifacts: [
      { label: 'Executive summary', detail: 'Available after the first completed scan.' },
      { label: 'Technical appendix', detail: 'Available after the first completed scan.' },
      { label: 'JSON export', detail: 'Available after the first completed scan.' },
    ],
  }
}

function buildLiveReport(scan = {}, results = {}) {
  const findingsCount = Array.isArray(results.findings) ? results.findings.length : 0
  const targetUrl = scan.targetUrl ?? results.targetUrl ?? 'Unknown target'
  const scanType = scan.scanType ?? results.scanType ?? 'Unknown'

  return {
    id: String(scan.id ?? results.id ?? ''),
    generatedAt: scan.createdAt ?? new Date().toISOString(),
    format: 'PDF + JSON',
    size: findingsCount ? `${findingsCount} findings` : 'No findings',
    scope: targetUrl,
    summary: `Report for ${targetUrl} (${scanType}). Use Download PDF for the generated document or Export JSON for the structured payload.`,
    artifacts: [
      { label: 'Executive summary', detail: `Risk score: ${results.summary?.riskScore ?? 0}/100.` },
      { label: 'Technical appendix', detail: `${findingsCount} findings included in the result set.` },
      { label: 'JSON export', detail: 'Generated directly from the active frontend state.' },
    ],
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

function Surface({ className = '', children }) {
  return (
    <div className={`surface-card rounded-[2rem] border border-white/10 p-6 ${className}`}>
      {children}
    </div>
  )
}

function SectionHeader({ eyebrow, title, description, action }) {
  return (
    <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="text-sm font-medium uppercase tracking-[0.28em] text-violet-200/75">
          {eyebrow}
        </p>
        <h2 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">
          {title}
        </h2>
        {description ? (
          <p className="mt-3 max-w-2xl text-sm leading-7 text-slate-300 sm:text-base">
            {description}
          </p>
        ) : null}
      </div>
      {action}
    </div>
  )
}

function StatCard({ label, value, detail, tone = 'from-violet-500/20 to-cyan-400/10' }) {
  return (
    <article
      className={`rounded-[1.75rem] border border-white/10 bg-gradient-to-br ${tone} p-5`}
    >
      <p className="text-sm font-medium text-slate-300">{label}</p>
      <p className="mt-4 text-3xl font-semibold text-white">{value}</p>
      <p className="mt-3 text-sm leading-6 text-slate-400">{detail}</p>
    </article>
  )
}

function Gauge({ value }) {
  return (
    <div className="relative mx-auto flex h-48 w-48 items-center justify-center">
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: `conic-gradient(#8b5cf6 0deg, #22d3ee ${value * 3.6}deg, rgba(255,255,255,0.08) ${value * 3.6}deg 360deg)`,
        }}
      />
      <div className="absolute inset-4 rounded-full bg-slate-950/95 shadow-[inset_0_0_50px_rgba(15,23,42,0.7)]" />
      <div className="relative text-center">
        <p className="text-5xl font-semibold tracking-[-0.05em] text-white">{value}</p>
        <p className="mt-2 text-sm uppercase tracking-[0.26em] text-slate-400">Risk score</p>
      </div>
    </div>
  )
}

function SeverityChart({ items }) {
  const maxValue = Math.max(...items.map((item) => item.value), 1)

  return (
    <div className="space-y-4">
      {items.map((item) => (
        <div key={item.label}>
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="text-slate-200">{item.label}</span>
            <span className="text-white">{item.value}</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-white/8">
            <div
              className="h-full rounded-full bg-gradient-to-r from-violet-400 via-fuchsia-400 to-cyan-300 transition-[width] duration-700"
              style={{ width: `${(item.value / maxValue) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

function TrendChart({ points }) {
  const width = 320
  const height = 150
  const padding = 18
  const maxValue = Math.max(...points.map((point) => point.value), 1)
  const chartWidth = width - padding * 2
  const chartHeight = height - padding * 2
  const path = points
    .map((point, index) => {
      const x =
        padding + (index * chartWidth) / Math.max(points.length - 1, 1)
      const y = padding + chartHeight - (point.value / maxValue) * chartHeight
      return `${index === 0 ? 'M' : 'L'} ${x} ${y}`
    })
    .join(' ')

  return (
    <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/70 p-4">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-40 w-full">
        <defs>
          <linearGradient id="trendGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#8b5cf6" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
        </defs>
        {[0, 1, 2, 3].map((line) => (
          <line
            key={line}
            x1={padding}
            y1={padding + (chartHeight / 3) * line}
            x2={width - padding}
            y2={padding + (chartHeight / 3) * line}
            stroke="rgba(148, 163, 184, 0.14)"
            strokeDasharray="4 6"
          />
        ))}
        <path d={path} fill="none" stroke="url(#trendGradient)" strokeWidth="4" />
        {points.map((point, index) => {
          const x =
            padding + (index * chartWidth) / Math.max(points.length - 1, 1)
          const y = padding + chartHeight - (point.value / maxValue) * chartHeight

          return (
            <g key={point.label}>
              <circle cx={x} cy={y} r="5" fill="#f8fafc" />
              <text x={x} y={height - 4} textAnchor="middle" fill="#94a3b8" fontSize="11">
                {point.label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

function ToastViewport({ toasts, onDismiss }) {
  return (
    <div className="no-print fixed right-4 top-4 z-50 flex w-[min(92vw,22rem)] flex-col gap-3">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="toast-enter rounded-2xl border border-white/10 bg-slate-950/90 p-4 shadow-[0_18px_60px_rgba(2,6,23,0.55)] backdrop-blur-xl"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-white">{toast.title}</p>
              <p className="mt-1 text-sm leading-6 text-slate-300">{toast.description}</p>
            </div>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="rounded-full border border-white/10 px-2 py-1 text-xs text-slate-300 hover:bg-white/10"
            >
              ✕
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

function App() {
  const hasLoadedScansRef = useRef(false)
  const [page, setPage] = useState(getPageFromHash())
  const [dataSource, setDataSource] = useState('demo')
  const [loadingScans, setLoadingScans] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [toasts, setToasts] = useState([])
  const [scans, setScans] = useState(demoScans)
  const [currentScanId, setCurrentScanId] = useState(demoScans[0].id)
  const [statusData, setStatusData] = useState(demoStatus)
  const [resultsData, setResultsData] = useState(demoResults)
  const [reportData, setReportData] = useState(demoReport)
  const [isDemoRunning, setIsDemoRunning] = useState(false)
  const [formState, setFormState] = useState({
    targetUrl: demoResults.targetUrl,
    scanType: 'deep',
    checks: vulnerabilityChecks.reduce(
      (accumulator, item) => ({ ...accumulator, [item.id]: true }),
      {},
    ),
  })

  const pushToast = useCallback((title, description) => {
    setToasts((current) => {
      const lastToast = current[current.length - 1]
      if (lastToast?.title === title && lastToast?.description === description) {
        return current
      }

      return [
        ...current,
        {
          id: `${Date.now()}-${Math.random()}`,
          title,
          description,
        },
      ]
    })
  }, [])

  const removeToast = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  useEffect(() => {
    if (!toasts.length) {
      return undefined
    }

    const timer = window.setTimeout(() => {
      setToasts((current) => current.slice(1))
    }, 3600)

    return () => window.clearTimeout(timer)
  }, [toasts])

  useEffect(() => {
    const handleHashChange = () => {
      setPage(getPageFromHash())
    }

    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  const navigate = useCallback((nextPage) => {
    window.location.hash = nextPage
    setPage(nextPage)
  }, [])

  const selectedChecks = useMemo(
    () =>
      vulnerabilityChecks
        .filter((item) => formState.checks[item.id])
        .map((item) => item.label),
    [formState.checks],
  )

  const selectedCheckIds = useMemo(
    () =>
      vulnerabilityChecks
        .filter((item) => formState.checks[item.id])
        .map((item) => item.id),
    [formState.checks],
  )

  const currentScan = useMemo(
    () => scans.find((scan) => scan.id === currentScanId) ?? scans[0],
    [scans, currentScanId],
  )

  const latestScan = useMemo(() => scans[0], [scans])

  const dashboardMetrics = useMemo(
    () => [
      {
        label: 'Scans',
        value: String(scans.length),
        detail: 'Total scan records currently visible in the frontend.',
        tone: 'from-violet-500/20 to-fuchsia-400/10',
      },
      {
        label: 'Last scan',
        value: latestScan ? formatDateLabel(latestScan.createdAt) : '—',
        detail: latestScan ? latestScan.targetUrl : 'No scans available yet.',
        tone: 'from-cyan-500/20 to-sky-400/10',
      },
      {
        label: 'Risk score',
        value: `${resultsData.summary.riskScore}/100`,
        detail: 'Overall risk posture based on the most recent result set.',
        tone: 'from-fuchsia-500/20 to-violet-400/10',
      },
      {
        label: 'High / Medium / Low',
        value: `${resultsData.summary.high} / ${resultsData.summary.medium} / ${resultsData.summary.low}`,
        detail: 'Severity totals from the active result set.',
        tone: 'from-orange-500/20 to-amber-400/10',
      },
    ],
    [latestScan, resultsData.summary, scans.length],
  )

  const loadScans = useCallback(async () => {
    try {
      const payload = await getScans()
      const normalized = normalizeScans(payload)

      if (!normalized.length) {
        setScans([])
        setCurrentScanId('')
        setStatusData(buildEmptyStatus())
        setResultsData(buildEmptyResults())
        setReportData(buildEmptyReport())
        pushToast('Live API connected', 'No scans were returned yet, keeping the shell empty.')
        setDataSource('live')
        return
      }

      const ordered = sortScans(normalized)
      setScans(ordered)
      setCurrentScanId(ordered[0].id)
      setDataSource('live')
      pushToast('Live API connected', 'Dashboard data is now coming from /api/scans.')
    } catch (error) {
      setDataSource('demo')
      pushToast('API unavailable', 'Showing explicit demo data until /api/scans becomes reachable.')
    } finally {
      setLoadingScans(false)
    }
  }, [pushToast])

  const loadScanMeta = useCallback(
    async (scanId, silent = true) => {
      try {
        const payload = await getScan(scanId)
        const normalized = normalizeScan(payload)

        if (!normalized.id) {
          return null
        }

        setScans((current) => {
          const withoutCurrent = current.filter((scan) => scan.id !== normalized.id)
          return sortScans([normalized, ...withoutCurrent])
        })

        return normalized
      } catch (error) {
        if (!silent) {
          pushToast('Unable to load scan', error.message)
        }
        return null
      }
    },
    [pushToast],
  )

  const loadResults = useCallback(
    async (scanId, silent = true) => {
      try {
        const payload = await getScanResults(scanId)
        const normalized = normalizeResults(payload, currentScan)
        setResultsData(normalized)
        return normalized
      } catch (error) {
        if (!silent) {
          pushToast('Unable to load results', error.message)
        }
        return null
      }
    },
    [currentScan, pushToast],
  )

  const loadReport = useCallback(
    async (scanId) => {
      const activeScan = currentScan?.id === scanId ? currentScan : scans.find((scan) => scan.id === scanId)
      const normalized = buildLiveReport(activeScan, resultsData)
      setReportData(normalized)
      return normalized
    },
    [currentScan, resultsData, scans],
  )

  const loadStatus = useCallback(
    async (scanId, silent = true) => {
      try {
        const payload = await getScanStatus(scanId)
        const normalized = normalizeStatus(payload, currentScan)
        setStatusData(normalized)

        if (normalized.state === 'completed') {
          await loadResults(scanId, true)
          await loadReport(scanId, true)
        }

        return normalized
      } catch (error) {
        if (!silent) {
          pushToast('Unable to load progress', error.message)
        }
        return null
      }
    },
    [currentScan, loadReport, loadResults, pushToast],
  )

  const startDemoScan = useCallback(
    (fallbackReason) => {
      const scanId = `demo_${Date.now()}`
      const scanTypeLabel =
        scanTypeOptions.find((option) => option.id === formState.scanType)?.label ?? 'Deep'
      const newScan = {
        id: scanId,
        targetUrl: formState.targetUrl,
        scanType: scanTypeLabel,
        status: 'running',
        riskScore: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        createdAt: new Date().toISOString(),
      }

      setScans((current) => sortScans([newScan, ...current.filter((scan) => scan.id !== scanId)]))
      setCurrentScanId(scanId)
      setStatusData({
        id: scanId,
        state: 'running',
        percent: 6,
        currentStage: progressStages[0],
        stages: progressStages,
        logs: [
          {
            time: formatTimeLabel(Date.now()),
            level: 'info',
            message: `Queued ${scanTypeLabel} scan for ${formState.targetUrl}`,
          },
          {
            time: formatTimeLabel(Date.now() + 1000),
            level: 'info',
            message: `Enabled checks: ${selectedChecks.join(', ')}`,
          },
        ],
      })
      setResultsData(buildDemoResults(scanId, formState.targetUrl, scanTypeLabel))
      setReportData(buildDemoReport(scanId, formState.targetUrl, scanTypeLabel))
      setIsDemoRunning(true)
      navigate('progress')
      pushToast(
        fallbackReason ? 'Demo mode enabled' : 'Demo scan started',
        fallbackReason
          ? 'Live API was not reachable, so the frontend switched to an explicit demo scan flow.'
          : 'The frontend is animating a local scan flow so every screen remains reviewable.',
      )
    },
    [formState.scanType, formState.targetUrl, navigate, pushToast, selectedChecks],
  )

  useEffect(() => {
    if (hasLoadedScansRef.current) {
      return
    }

    hasLoadedScansRef.current = true
    loadScans()
  }, [loadScans])

  useEffect(() => {
    if (dataSource !== 'live' || !currentScanId) {
      return undefined
    }

    loadScanMeta(currentScanId, true)

    if (page === 'dashboard' || page === 'progress') {
      loadStatus(currentScanId, true)
    }

    if (page === 'dashboard' || page === 'results' || page === 'report') {
      loadResults(currentScanId, true)
    }

    if (page === 'report') {
      loadReport(currentScanId, true)
    }

    return undefined
  }, [currentScanId, dataSource, loadReport, loadResults, loadScanMeta, loadStatus, page])

  useEffect(() => {
    if (page !== 'progress' || dataSource !== 'live' || !currentScanId) {
      return undefined
    }

    const timer = window.setInterval(() => {
      loadStatus(currentScanId, true)
    }, 4000)

    return () => window.clearInterval(timer)
  }, [currentScanId, dataSource, loadStatus, page])

  useEffect(() => {
    if (!isDemoRunning) {
      return undefined
    }

    const timer = window.setInterval(() => {
      setStatusData((current) => {
        const nextPercent = Math.min(current.percent + 11, 100)
        const nextStage = inferStage(nextPercent)
        const nextLogs =
          nextStage !== current.currentStage
            ? [
                ...current.logs,
                {
                  time: formatTimeLabel(Date.now()),
                  level: nextPercent === 100 ? 'success' : 'info',
                  message:
                    nextPercent === 100
                      ? 'Final report packaged. Results are ready for review.'
                      : `${nextStage} completed and queued the next worker stage.`,
                },
              ].slice(-8)
            : current.logs

        return {
          ...current,
          percent: nextPercent,
          currentStage: nextStage,
          state: nextPercent === 100 ? 'completed' : 'running',
          logs: nextLogs,
        }
      })
    }, 900)

    return () => window.clearInterval(timer)
  }, [isDemoRunning])

  useEffect(() => {
    if (!isDemoRunning || statusData.state !== 'completed') {
      return
    }

    setIsDemoRunning(false)
    setScans((current) =>
      current.map((scan) =>
        scan.id === statusData.id
          ? {
              ...scan,
              status: 'completed',
              riskScore: resultsData.summary.riskScore,
              critical: resultsData.summary.critical,
              high: resultsData.summary.high,
              medium: resultsData.summary.medium,
              low: resultsData.summary.low,
            }
          : scan,
      ),
    )
    pushToast('Demo scan completed', 'Results and report data are ready for review.')
  }, [isDemoRunning, pushToast, resultsData.summary, statusData.id, statusData.state])

  const handleStartScan = async () => {
    if (!formState.targetUrl) {
      pushToast('Target URL required', 'Enter a website URL before starting the scan.')
      return
    }

    if (!selectedCheckIds.length) {
      pushToast('Select at least one check', 'Enable at least one vulnerability module.')
      return
    }

    setSubmitting(true)

    if (dataSource === 'demo') {
      startDemoScan(false)
      setSubmitting(false)
      return
    }

    try {
      const payload = await createScan({
        targetUrl: formState.targetUrl,
        scanType: scanTypeApiMap[formState.scanType] ?? 'FULL',
        checks: selectedCheckIds.map((checkId) => checkTypeApiMap[checkId] ?? checkId),
      })
      const scanId = String(payload?.id ?? payload?.scanId ?? payload?.data?.id ?? '')

      if (!scanId) {
        throw new Error('Scan created but the API response did not include an id.')
      }

      const scanTypeLabel =
        scanTypeOptions.find((option) => option.id === formState.scanType)?.label ?? 'Deep'
      const optimisticScan = {
        id: scanId,
        targetUrl: formState.targetUrl,
        scanType: scanTypeLabel,
        status: 'queued',
        riskScore: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        createdAt: new Date().toISOString(),
      }

      setScans((current) =>
        sortScans([optimisticScan, ...current.filter((scan) => scan.id !== scanId)]),
      )
      setCurrentScanId(scanId)
      navigate('progress')
      pushToast('Scan started', `${formState.targetUrl} was submitted to POST /api/scans.`)
      await loadStatus(scanId, true)
    } catch (error) {
      pushToast('Unable to start live scan', error.message)
      if (error?.name === 'TypeError' || error?.status >= 500) {
        startDemoScan(true)
      }
    } finally {
      setSubmitting(false)
    }
  }

  const handleDownloadPdf = async () => {
    if (dataSource === 'live' && currentScanId) {
      try {
        const blob = await downloadScanReportPdf(currentScanId)
        downloadBlob(blob, `${currentScanId}-report.pdf`)
        pushToast('PDF downloaded', 'The report was downloaded from GET /api/scans/{id}/report.')
        return
      } catch (error) {
        pushToast('PDF download failed', error.message)
      }
    }

    window.print()
    pushToast('Print dialog opened', 'Demo mode uses browser print for the PDF handoff.')
  }

  const handleExportJson = () => {
    const payload = {
      scan: currentScan,
      status: statusData,
      results: resultsData,
      report: reportData,
    }

    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    })

    downloadBlob(blob, `${currentScan?.id ?? 'scan'}-results.json`)
    pushToast('JSON exported', 'Results were exported from the active frontend state.')
  }

  const handleRerunScan = () => {
    setFormState((current) => ({
      ...current,
      targetUrl: currentScan?.targetUrl ?? current.targetUrl,
    }))
    navigate('scan')
  }

  const progressIndex = Math.max(
    0,
    progressStages.findIndex((stage) => stage === statusData.currentStage),
  )

  const progressAction =
    statusData.state === 'completed' ? (
      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          onClick={() => navigate('results')}
          className="rounded-2xl bg-white px-4 py-3 text-sm font-semibold text-slate-950"
        >
          Open Results
        </button>
        <button
          type="button"
          onClick={() => navigate('report')}
          className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-white"
        >
          Open Report
        </button>
      </div>
    ) : null

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="hero-orb pointer-events-none absolute -left-24 top-0 h-72 w-72 rounded-full bg-violet-500/20 blur-[110px]" />
      <div className="hero-orb pointer-events-none absolute right-0 top-20 h-80 w-80 rounded-full bg-cyan-400/15 blur-[120px]" />
      <ToastViewport toasts={toasts} onDismiss={removeToast} />

      <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-6 py-6 sm:px-8 lg:px-10">
        <header className="no-print surface-card rounded-[2rem] border border-white/10 px-5 py-4">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-white/15 bg-white/10 text-lg font-semibold text-violet-100 shadow-[0_18px_40px_rgba(91,33,182,0.35)]">
                A
              </div>
              <div>
                <p className="text-sm font-semibold uppercase tracking-[0.3em] text-violet-200/75">
                  allscan
                </p>
                <p className="mt-1 text-sm text-slate-300">
                  Dark UI for landing, scanning, results, and reporting.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-medium text-slate-200">
                {loadingScans ? 'Loading scans...' : dataSource === 'live' ? 'Live API' : 'Demo data'}
              </span>
              <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-3 py-1 text-xs font-medium text-emerald-100">
                Responsive dark theme
              </span>
            </div>
          </div>

          <nav className="mt-5 flex flex-wrap gap-2" aria-label="Primary">
            {appPages.map((item) => {
              const isActive = item.id === page

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(item.id)}
                  className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                    isActive
                      ? 'bg-white text-slate-950'
                      : 'border border-white/10 bg-white/5 text-slate-200 hover:bg-white/10'
                  }`}
                >
                  {item.label}
                </button>
              )
            })}
          </nav>
        </header>

        <main className="flex-1 py-8">
          {page === 'landing' ? (
            <div className="space-y-8">
              <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
                <Surface className="overflow-hidden">
                  <div className="flex flex-wrap gap-2">
                    {landingFeatures.map((feature) => (
                      <span
                        key={feature}
                        className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-100"
                      >
                        {feature}
                      </span>
                    ))}
                  </div>
                  <h1 className="mt-6 max-w-4xl text-5xl font-semibold tracking-[-0.06em] text-white sm:text-6xl lg:text-7xl">
                    Frontend shell for a premium
                    <span className="block bg-gradient-to-r from-violet-200 via-white to-cyan-200 bg-clip-text text-transparent">
                      website security scanner
                    </span>
                  </h1>
                  <p className="mt-5 max-w-2xl text-lg leading-8 text-slate-300">
                    Hero section, supported vulnerabilities, strong CTA, dashboard summaries,
                    scan workflow, progress logs, detailed results, and report actions are all
                    present in one polished React frontend.
                  </p>
                  <div className="mt-8 flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={() => navigate('scan')}
                      className="rounded-2xl bg-white px-5 py-4 text-sm font-semibold text-slate-950"
                    >
                      Start Scan
                    </button>
                    <button
                      type="button"
                      onClick={() => navigate('dashboard')}
                      className="rounded-2xl border border-white/10 bg-white/5 px-5 py-4 text-sm font-semibold text-white"
                    >
                      Open Dashboard
                    </button>
                  </div>
                </Surface>

                <Surface className="relative">
                  <div className="absolute right-6 top-6 rounded-full border border-cyan-400/25 bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-100">
                    CTA-ready
                  </div>
                  <p className="text-sm font-medium uppercase tracking-[0.28em] text-slate-400">
                    Advantages
                  </p>
                  <div className="mt-6 space-y-4">
                    {advantageCards.map((card) => (
                      <article
                        key={card.title}
                        className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5"
                      >
                        <h3 className="text-lg font-semibold text-white">{card.title}</h3>
                        <p className="mt-2 text-sm leading-7 text-slate-300">{card.description}</p>
                      </article>
                    ))}
                  </div>
                </Surface>
              </section>

              <section className="grid gap-6 lg:grid-cols-3">
                {capabilityCards.map((card) => (
                  <Surface key={card.title}>
                    <h3 className="text-xl font-semibold text-white">{card.title}</h3>
                    <p className="mt-3 text-sm leading-7 text-slate-300">{card.description}</p>
                  </Surface>
                ))}
              </section>

              <section className="space-y-6">
                <SectionHeader
                  eyebrow="Supported vulnerabilities"
                  title="Coverage built into the product story"
                  description="The landing page calls out the major issue classes your scanner surfaces so the offer is immediately understandable."
                />
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {supportedVulnerabilities.map((item) => (
                    <Surface key={item.title} className="bg-white/[0.03]">
                      <div className="flex items-center justify-between gap-3">
                        <h3 className="text-lg font-semibold text-white">{item.title}</h3>
                        <span className="rounded-full border border-white/10 px-3 py-1 text-xs text-slate-200">
                          {item.tag}
                        </span>
                      </div>
                      <p className="mt-3 text-sm leading-7 text-slate-300">{item.detail}</p>
                    </Surface>
                  ))}
                </div>
              </section>

              <footer className="rounded-[2rem] border border-white/10 bg-white/[0.03] px-6 py-5 text-sm text-slate-400">
                Footer: allscan frontend concept with landing, dashboard, scan workflow,
                results, report actions, charts, animations, and toast notifications.
              </footer>
            </div>
          ) : null}

          {page === 'dashboard' ? (
            <div className="space-y-8">
              <SectionHeader
                eyebrow="Dashboard"
                title="Operational overview"
                description="Track total scans, last activity, overall risk score, and severity distribution from one dark-themed control panel."
                action={
                  <button
                    type="button"
                    onClick={loadScans}
                    className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-white"
                  >
                    Refresh scans
                  </button>
                }
              />

              <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                {dashboardMetrics.map((card) => (
                  <StatCard
                    key={card.label}
                    label={card.label}
                    value={card.value}
                    detail={card.detail}
                    tone={card.tone}
                  />
                ))}
              </section>

              <section className="grid gap-6 lg:grid-cols-[0.8fr_1.2fr]">
                <Surface>
                  <p className="text-sm font-medium text-slate-400">Overall risk score</p>
                  <div className="mt-6">
                    <Gauge value={resultsData.summary.riskScore} />
                  </div>
                </Surface>

                <Surface>
                  <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
                    <div>
                      <p className="text-sm font-medium text-slate-400">Severity chart</p>
                      <div className="mt-5">
                        <SeverityChart items={resultsData.severityChart} />
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-400">Risk trend</p>
                      <div className="mt-5">
                        <TrendChart points={resultsData.trend} />
                      </div>
                    </div>
                  </div>
                </Surface>
              </section>

              <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
                <Surface>
                  <p className="text-sm font-medium text-slate-400">Recent scans</p>
                  <div className="mt-5 overflow-hidden rounded-[1.5rem] border border-white/10">
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-white/10 text-left">
                        <thead className="bg-slate-950/80 text-xs uppercase tracking-[0.24em] text-slate-500">
                          <tr>
                            <th className="px-4 py-4 font-medium">Target</th>
                            <th className="px-4 py-4 font-medium">Type</th>
                            <th className="px-4 py-4 font-medium">Status</th>
                            <th className="px-4 py-4 font-medium">Risk</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/8 bg-white/[0.03]">
                          {scans.length ? (
                            scans.map((scan) => (
                              <tr key={scan.id}>
                                <td className="px-4 py-4">
                                  <p className="font-medium text-white">{scan.targetUrl}</p>
                                  <p className="mt-1 text-sm text-slate-400">{formatDateLabel(scan.createdAt)}</p>
                                </td>
                                <td className="px-4 py-4 text-sm text-slate-200">{scan.scanType}</td>
                                <td className="px-4 py-4">
                                  <span className="rounded-full border border-white/10 px-3 py-1 text-xs text-slate-200">
                                    {prettifyStatus(scan.status)}
                                  </span>
                                </td>
                                <td className="px-4 py-4 text-sm text-slate-200">
                                  {scan.riskScore ? `${scan.riskScore}/100` : 'Pending'}
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan="4" className="px-4 py-8 text-center text-sm text-slate-400">
                                Live API is connected, but there are no scans yet. Start the first scan
                                from the Scan page.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </Surface>

                <Surface>
                  <p className="text-sm font-medium text-slate-400">API integration</p>
                  <div className="mt-5 space-y-3">
                    {[
                      'POST /api/scans',
                      'GET /api/scans',
                      'GET /api/scans/{id}',
                      'GET /api/scans/{id}/status',
                      'GET /api/scans/{id}/results',
                      'GET /api/scans/{id}/report',
                    ].map((route) => (
                      <div
                        key={route}
                        className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-slate-200"
                      >
                        {route}
                      </div>
                    ))}
                  </div>
                </Surface>
              </section>
            </div>
          ) : null}

          {page === 'scan' ? (
            <div className="space-y-8">
              <SectionHeader
                eyebrow="Scan page"
                title="Launch a new security scan"
                description="Target URL, scan type presets, vulnerability checkboxes, and a clear primary action are ready for frontend API integration."
              />

              <section className="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
                <Surface>
                  <form
                    className="space-y-6"
                    onSubmit={(event) => {
                      event.preventDefault()
                      handleStartScan()
                    }}
                  >
                    <label className="block">
                      <span className="mb-3 block text-sm font-medium text-slate-300">
                        Target URL
                      </span>
                      <input
                        type="url"
                        value={formState.targetUrl}
                        onChange={(event) =>
                          setFormState((current) => ({
                            ...current,
                            targetUrl: event.target.value,
                          }))
                        }
                        placeholder="https://target-site.com"
                        className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-4 text-white outline-none placeholder:text-slate-500 focus:border-violet-300/40"
                      />
                    </label>

                    <div>
                      <p className="mb-3 text-sm font-medium text-slate-300">Scan Type</p>
                      <div className="grid gap-3 md:grid-cols-3">
                        {scanTypeOptions.map((option) => {
                          const active = formState.scanType === option.id

                          return (
                            <button
                              key={option.id}
                              type="button"
                              onClick={() =>
                                setFormState((current) => ({
                                  ...current,
                                  scanType: option.id,
                                }))
                              }
                              className={`rounded-[1.5rem] border p-4 text-left transition ${
                                active
                                  ? 'border-violet-300/40 bg-violet-400/10'
                                  : 'border-white/10 bg-white/[0.03] hover:bg-white/[0.06]'
                              }`}
                            >
                              <p className="text-sm font-semibold text-white">{option.label}</p>
                              <p className="mt-2 text-xs leading-6 text-slate-300">
                                {option.description}
                              </p>
                            </button>
                          )
                        })}
                      </div>
                    </div>

                    <div>
                      <p className="mb-3 text-sm font-medium text-slate-300">Checks</p>
                      <div className="grid gap-3 md:grid-cols-2">
                        {vulnerabilityChecks.map((item) => (
                          <label
                            key={item.id}
                            className="flex cursor-pointer items-start gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4"
                          >
                            <input
                              type="checkbox"
                              checked={formState.checks[item.id]}
                              onChange={(event) =>
                                setFormState((current) => ({
                                  ...current,
                                  checks: {
                                    ...current.checks,
                                    [item.id]: event.target.checked,
                                  },
                                }))
                              }
                              className="mt-1 h-4 w-4 rounded border-white/10 bg-white/5"
                            />
                            <span>
                              <span className="block text-sm font-semibold text-white">
                                {item.label}
                              </span>
                              <span className="mt-1 block text-sm leading-6 text-slate-300">
                                {item.description}
                              </span>
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <button
                      type="submit"
                      disabled={submitting}
                      className="inline-flex w-full items-center justify-center rounded-2xl bg-white px-5 py-4 text-sm font-semibold text-slate-950 disabled:opacity-60"
                    >
                      {submitting ? 'Starting scan...' : 'Start Scan'}
                    </button>
                  </form>
                </Surface>

                <Surface>
                  <p className="text-sm font-medium text-slate-400">Launch summary</p>
                  <div className="mt-5 space-y-4">
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Mode</p>
                      <p className="mt-2 text-xl font-semibold text-white">
                        {scanTypeOptions.find((option) => option.id === formState.scanType)?.label}
                      </p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Modules</p>
                      <p className="mt-2 text-xl font-semibold text-white">{selectedChecks.length}</p>
                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        {selectedChecks.join(', ')}
                      </p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Data source</p>
                      <p className="mt-2 text-xl font-semibold text-white">
                        {dataSource === 'live' ? 'Live backend' : 'Explicit demo mode'}
                      </p>
                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        POST /api/scans is called when live mode is available; otherwise the UI
                        falls back with a visible toast and local demo progression.
                      </p>
                    </div>
                  </div>
                </Surface>
              </section>
            </div>
          ) : null}

          {page === 'progress' ? (
            <div className="space-y-8">
              <SectionHeader
                eyebrow="Scan progress page"
                title="Live progress, logs, and stage tracking"
                description="The frontend polls GET /api/scans/{id}/status in live mode and keeps an explicit animated demo path available when the backend is offline."
                action={progressAction}
              />

              <section className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
                <Surface>
                  <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-400">Current scan</p>
                      <h3 className="mt-2 text-2xl font-semibold text-white">
                        {currentScan?.targetUrl ?? 'No active scan yet'}
                      </h3>
                      <p className="mt-2 text-sm leading-7 text-slate-300">
                        {statusData.currentStage} • {prettifyStatus(statusData.state)}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs uppercase tracking-[0.26em] text-slate-500">Progress</p>
                      <p className="mt-2 text-4xl font-semibold text-white">{statusData.percent}%</p>
                    </div>
                  </div>

                  <div className="mt-6 h-4 overflow-hidden rounded-full bg-white/8">
                    <div
                      className="scan-progress-stripes h-full rounded-full bg-gradient-to-r from-violet-400 via-fuchsia-400 to-cyan-300 transition-[width] duration-700"
                      style={{ width: `${statusData.percent}%` }}
                    />
                  </div>

                  <div className="mt-6 space-y-3">
                    {progressStages.map((stage, index) => {
                      const active = statusData.currentStage === stage && statusData.state !== 'completed'
                      const done = index < progressIndex || statusData.state === 'completed'

                      return (
                        <div
                          key={stage}
                          className={`rounded-[1.5rem] border px-4 py-4 ${
                            active
                              ? 'border-violet-300/40 bg-violet-400/10'
                              : 'border-white/10 bg-white/[0.03]'
                          }`}
                        >
                          <div className="flex items-center gap-4">
                            <div
                              className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold ${
                                done
                                  ? 'bg-emerald-400/20 text-emerald-100'
                                  : active
                                    ? 'bg-violet-400/20 text-violet-100'
                                    : 'bg-white/10 text-slate-300'
                              }`}
                            >
                              {done ? '✓' : index + 1}
                            </div>
                            <div>
                              <p className="font-medium text-white">{stage}</p>
                              <p className="mt-1 text-sm text-slate-400">
                                {index === progressIndex && statusData.state !== 'completed'
                                  ? 'Currently running'
                                  : done
                                    ? 'Completed'
                                    : 'Waiting'}
                              </p>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </Surface>

                <Surface>
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-medium text-slate-400">Live logs</p>
                      <p className="mt-2 text-sm leading-7 text-slate-300">
                        Terminal-style event feed for crawling, payload injection, and report
                        packaging.
                      </p>
                    </div>
                    <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-200">
                      {dataSource === 'live' ? 'Polling status endpoint' : 'Demo log stream'}
                    </span>
                  </div>

                  <div className="mt-6 grid gap-4 md:grid-cols-3">
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Scan ID</p>
                      <p className="mt-2 text-sm font-semibold text-white">{currentScanId || '—'}</p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Type</p>
                      <p className="mt-2 text-sm font-semibold text-white">{currentScan?.scanType ?? '—'}</p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Source</p>
                      <p className="mt-2 text-sm font-semibold text-white">
                        {dataSource === 'live' ? 'API' : 'Demo'}
                      </p>
                    </div>
                  </div>

                  <div className="mt-6 rounded-[1.5rem] border border-white/10 bg-slate-950/80 p-5 font-mono text-sm">
                    <div className="space-y-3">
                      {statusData.logs.map((log, index) => (
                        <div key={`${log.time}-${index}`} className="grid grid-cols-[72px_58px_1fr] gap-3">
                          <span className="text-slate-500">{log.time}</span>
                          <span className="text-violet-200">{log.level}</span>
                          <span className="text-slate-200">{log.message}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </Surface>
              </section>
            </div>
          ) : null}

          {page === 'results' ? (
            <div className="space-y-8">
              <SectionHeader
                eyebrow="Results page"
                title="Summary cards, vulnerability table, and OWASP mapping"
                description="This page surfaces the risk score, severity counts, detailed findings, and OWASP Top 10 panel in a layout ready for live API data."
                action={
                  <button
                    type="button"
                    onClick={() => navigate('report')}
                    className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-white"
                  >
                    Open report page
                  </button>
                }
              />

              <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                <StatCard
                  label="Risk Score"
                  value={`${resultsData.summary.riskScore}/100`}
                  detail="Overall weighted risk posture."
                />
                <StatCard
                  label="Critical"
                  value={String(resultsData.summary.critical)}
                  detail="Immediate remediation required."
                  tone="from-rose-500/20 to-red-400/10"
                />
                <StatCard
                  label="High"
                  value={String(resultsData.summary.high)}
                  detail="High-impact exploitable issues."
                  tone="from-orange-500/20 to-amber-400/10"
                />
                <StatCard
                  label="Medium"
                  value={String(resultsData.summary.medium)}
                  detail="Material gaps requiring follow-up."
                  tone="from-amber-500/20 to-yellow-400/10"
                />
                <StatCard
                  label="Low"
                  value={String(resultsData.summary.low)}
                  detail="Hardening recommendations."
                  tone="from-cyan-500/20 to-sky-400/10"
                />
              </section>

              <section className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
                <Surface className="overflow-hidden">
                  <p className="text-sm font-medium text-slate-400">Vulnerability table</p>
                  <div className="mt-5 overflow-x-auto rounded-[1.5rem] border border-white/10">
                    <table className="min-w-full divide-y divide-white/10 text-left">
                      <thead className="bg-slate-950/80 text-xs uppercase tracking-[0.24em] text-slate-500">
                        <tr>
                          <th className="px-4 py-4 font-medium">Type</th>
                          <th className="px-4 py-4 font-medium">Severity</th>
                          <th className="px-4 py-4 font-medium">URL</th>
                          <th className="px-4 py-4 font-medium">Parameter</th>
                          <th className="px-4 py-4 font-medium">Description</th>
                          <th className="px-4 py-4 font-medium">Recommendation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/8 bg-white/[0.03]">
                        {resultsData.findings.map((finding) => (
                          <tr key={`${finding.type}-${finding.url}-${finding.parameter}`}>
                            <td className="px-4 py-4">
                              <p className="font-medium text-white">{finding.type}</p>
                              <p className="mt-1 text-xs text-slate-500">{finding.owasp}</p>
                            </td>
                            <td className="px-4 py-4">
                              <span
                                className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${severityStyles[finding.severity] ?? severityStyles.Low}`}
                              >
                                {finding.severity}
                              </span>
                            </td>
                            <td className="px-4 py-4 text-sm text-slate-200">{finding.url}</td>
                            <td className="px-4 py-4 text-sm text-slate-200">{finding.parameter}</td>
                            <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                              {finding.description}
                            </td>
                            <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                              {finding.recommendation}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Surface>

                <div className="space-y-6">
                  <Surface>
                    <p className="text-sm font-medium text-slate-400">OWASP mapping panel</p>
                    <div className="mt-5 space-y-3">
                      {resultsData.owaspMappings.map((item) => (
                        <div
                          key={`${item.code}-${item.title}`}
                          className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <p className="text-sm font-semibold text-white">
                              {item.code} {item.title}
                            </p>
                            <span className="rounded-full border border-white/10 px-3 py-1 text-xs text-slate-200">
                              {item.count}
                            </span>
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-300">{item.description}</p>
                        </div>
                      ))}
                    </div>
                  </Surface>

                  <Surface>
                    <p className="text-sm font-medium text-slate-400">Severity chart</p>
                    <div className="mt-5">
                      <SeverityChart items={resultsData.severityChart} />
                    </div>
                  </Surface>
                </div>
              </section>
            </div>
          ) : null}

          {page === 'report' ? (
            <div className="space-y-8">
              <SectionHeader
                eyebrow="Report page"
                title="Download, export, and rerun actions"
                description="Report actions are wired for PDF and JSON exports, with a rerun flow that jumps the operator back into the launch form."
                action={
                  <div className="no-print flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={handleDownloadPdf}
                      className="rounded-2xl bg-white px-4 py-3 text-sm font-semibold text-slate-950"
                    >
                      Download PDF
                    </button>
                    <button
                      type="button"
                      onClick={handleExportJson}
                      className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-white"
                    >
                      Export JSON
                    </button>
                    <button
                      type="button"
                      onClick={handleRerunScan}
                      className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-white"
                    >
                      Re-run Scan
                    </button>
                  </div>
                }
              />

              <section className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
                <Surface>
                  <p className="text-sm font-medium text-slate-400">Report summary</p>
                  <div className="mt-5 grid gap-4 sm:grid-cols-2">
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Generated</p>
                      <p className="mt-2 text-sm font-semibold text-white">
                        {formatDateLabel(reportData.generatedAt)}
                      </p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Format</p>
                      <p className="mt-2 text-sm font-semibold text-white">{reportData.format}</p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Size</p>
                      <p className="mt-2 text-sm font-semibold text-white">{reportData.size}</p>
                    </div>
                    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Scope</p>
                      <p className="mt-2 text-sm font-semibold text-white">{reportData.scope}</p>
                    </div>
                  </div>
                  <p className="mt-5 text-sm leading-7 text-slate-300">{reportData.summary}</p>
                </Surface>

                <Surface className="print-shell">
                  <p className="text-sm font-medium text-slate-400">Artifacts</p>
                  <div className="mt-5 space-y-4">
                    {reportData.artifacts.map((artifact) => (
                      <article
                        key={artifact.label}
                        className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5"
                      >
                        <h3 className="text-lg font-semibold text-white">{artifact.label}</h3>
                        <p className="mt-2 text-sm leading-7 text-slate-300">{artifact.detail}</p>
                      </article>
                    ))}
                  </div>
                </Surface>
              </section>
            </div>
          ) : null}
        </main>
      </div>
    </div>
  )
}

export default App
