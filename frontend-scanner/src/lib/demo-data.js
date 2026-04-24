export const appPages = [
  { id: 'landing', label: 'Landing' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan' },
  { id: 'progress', label: 'Progress' },
  { id: 'results', label: 'Results' },
  { id: 'report', label: 'Report' },
]

export const scanTypeOptions = [
  {
    id: 'fast',
    label: 'Fast',
    description: 'Rapid perimeter scan for surface-level risk and hardening gaps.',
  },
  {
    id: 'deep',
    label: 'Deep',
    description: 'Balanced crawl plus active payload testing across routes and forms.',
  },
  {
    id: 'owasp-full',
    label: 'Full OWASP',
    description: 'Expanded testing profile mapped against OWASP Top 10 coverage.',
  },
]

export const vulnerabilityChecks = [
  { id: 'xss', label: 'XSS', description: 'Reflected and stored input handling checks.' },
  { id: 'sqli', label: 'SQLi', description: 'Injection probes for authentication and search flows.' },
  { id: 'csrf', label: 'CSRF', description: 'Cross-site request forgery coverage on state changes.' },
  { id: 'directoryScan', label: 'Directory Scan', description: 'Enumeration of exposed folders and archives.' },
  { id: 'configLeak', label: 'Config Leak', description: 'Leaked env, backup, and config artifacts.' },
]

export const landingFeatures = [
  'Scan your website in seconds',
  'OWASP Top 10 classification',
  'PDF and JSON exports',
  'Executive-ready dashboard',
]

export const capabilityCards = [
  {
    title: 'Hero-grade first impression',
    description: 'Premium motion, glow layers, and strong CTA hierarchy for demo and sales usage.',
  },
  {
    title: 'Operator dashboard',
    description: 'Live metrics, charts, recent scans, and risk posture at a glance.',
  },
  {
    title: 'Investigation workflow',
    description: 'Launch scans, follow progress, review findings, and export the report from one shell.',
  },
]

export const supportedVulnerabilities = [
  { title: 'Cross-Site Scripting', tag: 'XSS', detail: 'Output encoding and client-side injection checks.' },
  { title: 'SQL Injection', tag: 'SQLi', detail: 'Unsafe query construction and auth bypass paths.' },
  { title: 'Cross-Site Request Forgery', tag: 'CSRF', detail: 'Token enforcement and origin validation.' },
  { title: 'Open Directories', tag: 'DIR', detail: 'Browsable folders, archives, and static leaks.' },
  { title: 'Configuration Leaks', tag: 'CFG', detail: 'Public backups, env files, and server metadata.' },
  { title: 'Header Hardening', tag: 'HDR', detail: 'CSP, HSTS, X-Frame-Options, and transport policy.' },
]

export const advantageCards = [
  {
    title: 'Fast onboarding',
    description: 'Clear scan presets and guided launch flow for operators and non-technical stakeholders.',
  },
  {
    title: 'Actionable findings',
    description: 'Recommendations, parameters, URLs, and OWASP mapping are surfaced together.',
  },
  {
    title: 'Executive artifacts',
    description: 'PDF-ready report actions and structured JSON export for downstream tooling.',
  },
  {
    title: 'Dark responsive UI',
    description: 'Built to look polished on large screens, laptops, and mobile handoffs.',
  },
]

export const progressStages = [
  'Crawling pages',
  'Testing forms',
  'Injecting payloads',
  'Checking files',
  'Finalizing report',
]

export const demoScans = [
  {
    id: 'scan_401',
    targetUrl: 'https://acme-store.com',
    scanType: 'Deep',
    status: 'completed',
    riskScore: 78,
    critical: 1,
    high: 3,
    medium: 7,
    low: 11,
    createdAt: '2026-04-24T08:05:00Z',
  },
  {
    id: 'scan_400',
    targetUrl: 'https://northwind.app',
    scanType: 'Fast',
    status: 'completed',
    riskScore: 59,
    critical: 0,
    high: 2,
    medium: 5,
    low: 8,
    createdAt: '2026-04-23T16:10:00Z',
  },
  {
    id: 'scan_399',
    targetUrl: 'https://billing.futura.dev',
    scanType: 'Full OWASP',
    status: 'running',
    riskScore: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    createdAt: '2026-04-23T12:30:00Z',
  },
  {
    id: 'scan_398',
    targetUrl: 'https://portal.evex.io',
    scanType: 'Deep',
    status: 'completed',
    riskScore: 66,
    critical: 1,
    high: 1,
    medium: 6,
    low: 9,
    createdAt: '2026-04-22T10:20:00Z',
  },
]

export const demoResults = {
  id: 'scan_401',
  targetUrl: 'https://acme-store.com',
  scanType: 'Deep',
  summary: {
    riskScore: 78,
    critical: 1,
    high: 3,
    medium: 7,
    low: 11,
  },
  findings: [
    {
      type: 'SQL Injection',
      severity: 'Critical',
      url: '/login',
      parameter: 'username',
      description: 'Authentication input reaches a SQL sink without parameterization.',
      recommendation: 'Use prepared statements and server-side input validation.',
      owasp: 'A03 Injection',
    },
    {
      type: 'Reflected XSS',
      severity: 'High',
      url: '/search',
      parameter: 'q',
      description: 'User-controlled data is reflected into HTML without escaping.',
      recommendation: 'Encode output by context and add a strict CSP.',
      owasp: 'A03 Injection',
    },
    {
      type: 'Open Directory Listing',
      severity: 'High',
      url: '/backup/',
      parameter: '-',
      description: 'Public directory index exposes backup archive names.',
      recommendation: 'Disable directory browsing and remove sensitive files from public storage.',
      owasp: 'A05 Security Misconfiguration',
    },
    {
      type: 'Broken Access Control',
      severity: 'High',
      url: '/admin/users',
      parameter: 'role',
      description: 'Privilege checks are missing for a sensitive administrative route.',
      recommendation: 'Enforce authorization on every server-side access path.',
      owasp: 'A01 Broken Access Control',
    },
    {
      type: 'Missing CSRF Protection',
      severity: 'Medium',
      url: '/profile',
      parameter: 'email',
      description: 'Profile update endpoint accepts state-changing requests without a CSRF token.',
      recommendation: 'Require CSRF tokens or same-site protection on write operations.',
      owasp: 'A01 Broken Access Control',
    },
    {
      type: 'Config Leak',
      severity: 'Medium',
      url: '/.env.backup',
      parameter: '-',
      description: 'A backup environment file is reachable over the public web root.',
      recommendation: 'Move secrets out of the public directory and rotate exposed credentials.',
      owasp: 'A05 Security Misconfiguration',
    },
  ],
  owaspMappings: [
    {
      code: 'A03',
      title: 'Injection',
      count: 2,
      description: 'Unsafe input handling leads to code or query execution risk.',
    },
    {
      code: 'A05',
      title: 'Security Misconfiguration',
      count: 2,
      description: 'Publicly exposed assets and missing hardening headers increase attack surface.',
    },
    {
      code: 'A01',
      title: 'Broken Access Control',
      count: 2,
      description: 'Authorization and request integrity gaps enable unauthorized actions.',
    },
  ],
  severityChart: [
    { label: 'Critical', value: 1 },
    { label: 'High', value: 3 },
    { label: 'Medium', value: 7 },
    { label: 'Low', value: 11 },
  ],
  trend: [
    { label: 'Mon', value: 42 },
    { label: 'Tue', value: 57 },
    { label: 'Wed', value: 61 },
    { label: 'Thu', value: 54 },
    { label: 'Fri', value: 78 },
  ],
}

export const demoStatus = {
  id: 'scan_401',
  state: 'running',
  percent: 68,
  currentStage: 'Injecting payloads',
  stages: progressStages,
  logs: [
    { time: '13:31:02', level: 'info', message: 'Queued scan for https://acme-store.com' },
    { time: '13:31:05', level: 'info', message: 'Crawler discovered 26 routes and 9 forms.' },
    { time: '13:31:10', level: 'info', message: 'Testing login, search, checkout, and profile forms.' },
    { time: '13:31:16', level: 'warn', message: 'Potential SQLi vector detected on /login?username=' },
    { time: '13:31:19', level: 'info', message: 'Injecting XSS and SQLi payload suites into dynamic parameters.' },
  ],
}

export const demoReport = {
  id: 'scan_401',
  generatedAt: '2026-04-24T08:15:00Z',
  format: 'PDF + JSON',
  size: '1.8 MB',
  scope: '26 routes, 9 forms, 128 payloads',
  summary: 'Critical injection and access control issues require immediate remediation.',
  artifacts: [
    { label: 'Executive summary', detail: 'Business risk overview and remediation priority.' },
    { label: 'Technical appendix', detail: 'Per-finding evidence, parameters, and recommendations.' },
    { label: 'JSON export', detail: 'Machine-readable results for pipelines or ticketing systems.' },
  ],
}
