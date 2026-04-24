import json
import os
import textwrap
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from engine import Crawler, ScanOrchestrator
from modules.configs import check_configs
from modules.sqli import check_sqli
from modules.xss import check_xss

HOST = os.getenv("ALLSCAN_API_HOST", "127.0.0.1")
PORT = int(os.getenv("ALLSCAN_API_PORT", "8000"))
ALLOWED_ORIGIN = os.getenv("ALLSCAN_ALLOWED_ORIGIN", "*")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")

os.makedirs(REPORTS_DIR, exist_ok=True)

SCAN_TYPE_LABELS = {
    "fast": "Fast",
    "quick": "Fast",
    "deep": "Deep",
    "full": "Full OWASP",
    "owaspfull": "Full OWASP",
}

CHECK_HANDLERS = {
    "xss": check_xss,
    "sqli": check_sqli,
    "configleak": check_configs,
    "leakage": check_configs,
    "directoryscan": check_configs,
    "open_directories": check_configs,
}

FINDING_METADATA = {
    "SQL Injection": {
        "severity": "High",
        "description": "Input reached a database-facing path with injectable payload behavior.",
        "recommendation": "Use parameterized queries and validate user input on the server side.",
        "owasp": "A03 Injection",
    },
    "Reflected XSS": {
        "severity": "Medium",
        "description": "User-controlled content was reflected into the response without safe encoding.",
        "recommendation": "Escape output by context and add a restrictive Content Security Policy.",
        "owasp": "A03 Injection",
    },
    "Security Misconfiguration": {
        "severity": "High",
        "description": "Sensitive files or server configuration details were exposed publicly.",
        "recommendation": "Remove public access to secrets, backups, and diagnostic endpoints.",
        "owasp": "A05 Security Misconfiguration",
    },
}

PROGRESS_STAGES = [
    "Queued",
    "Crawling pages",
    "Testing forms",
    "Injecting payloads",
    "Checking files",
    "Finalizing report",
]

store_lock = threading.Lock()
scan_store = {}
scan_order = []


def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().isoformat().replace("+00:00", "Z")


def display_time():
    return now_utc().strftime("%H:%M:%S")


def normalize_token(value):
    return "".join(char for char in str(value).lower() if char.isalnum() or char == "_")


def resolve_scan_type(value):
    token = normalize_token(value)
    return SCAN_TYPE_LABELS.get(token, "Deep")


def resolve_checks(raw_checks):
    if not raw_checks:
        return [check_xss, check_sqli, check_configs], []

    selected = []
    unsupported = []

    for check_name in raw_checks:
        token = normalize_token(check_name)
        handler = CHECK_HANDLERS.get(token)
        if handler is None:
            unsupported.append(str(check_name))
            continue
        if handler not in selected:
            selected.append(handler)

    return selected, unsupported


def resolve_depth(scan_type):
    token = normalize_token(scan_type)
    if token in {"fast", "quick"}:
        return 1
    if token in {"full", "owaspfull"}:
        return 4
    return 3


def scan_report_path(scan_id):
    return os.path.join(REPORTS_DIR, f"{scan_id}.json")


def summarize_findings(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for finding in findings:
        severity = finding.get("severity", "Low")
        if severity not in counts:
            severity = "Low"
        counts[severity] += 1

    risk_score = min(
        100,
        counts["Critical"] * 30 + counts["High"] * 20 + counts["Medium"] * 10 + counts["Low"] * 4,
    )

    return {
        "critical": counts["Critical"],
        "high": counts["High"],
        "medium": counts["Medium"],
        "low": counts["Low"],
        "riskScore": risk_score,
    }


def build_owasp_mappings(findings):
    grouped = {}

    for finding in findings:
        label = finding.get("owaspCategory", "Unmapped")
        if label not in grouped:
            parts = label.split(" ", 1)
            grouped[label] = {
                "code": parts[0],
                "title": parts[1] if len(parts) > 1 else label,
                "count": 0,
                "description": "Mapped automatically from detected findings.",
            }
        grouped[label]["count"] += 1

    return list(grouped.values())


def format_finding(raw_finding):
    finding_type = raw_finding.get("type", "Unknown")
    metadata = FINDING_METADATA.get(finding_type, {})

    return {
        "id": str(uuid.uuid4()),
        "type": finding_type,
        "severity": metadata.get("severity", "Low"),
        "url": raw_finding.get("url", ""),
        "parameter": raw_finding.get("parameter") or raw_finding.get("payload") or "-",
        "description": metadata.get("description", "Potential security issue detected by the scanner."),
        "recommendation": raw_finding.get("ai_remediation")
        or metadata.get("recommendation", "Review and patch the affected flow."),
        "owaspCategory": metadata.get("owasp", "Unmapped"),
        "payload": raw_finding.get("payload", ""),
        "aiRemediation": raw_finding.get("ai_remediation", ""),
    }


def build_manual_targets(target_url):
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return [
        {"url": f"{base}/rest/products/search", "method": "GET", "params": ["q"]},
        {"url": f"{base}/rest/user/login", "method": "POST", "params": ["email", "password"]},
        {"url": f"{base}/api/Feedbacks", "method": "POST", "params": ["comment"]},
    ]


def create_scan_record(target_url, scan_type, checks, unsupported_checks):
    scan_id = str(uuid.uuid4())
    record = {
        "id": scan_id,
        "targetUrl": target_url,
        "scanType": resolve_scan_type(scan_type),
        "requestedChecks": list(checks or []),
        "unsupportedChecks": list(unsupported_checks),
        "status": "queued",
        "progress": 0,
        "stage": PROGRESS_STAGES[0],
        "createdAt": iso_now(),
        "logs": [
            {
                "time": display_time(),
                "level": "info",
                "message": f"Queued scan for {target_url}",
            }
        ],
        "results": None,
        "report": None,
    }

    if unsupported_checks:
        record["logs"].append(
            {
                "time": display_time(),
                "level": "warning",
                "message": f"Unsupported checks skipped: {', '.join(unsupported_checks)}",
            }
        )

    with store_lock:
        scan_store[scan_id] = record
        scan_order.insert(0, scan_id)

    return record


def get_scan_or_none(scan_id):
    with store_lock:
        return scan_store.get(scan_id)


def append_log(scan_id, level, message):
    with store_lock:
        record = scan_store[scan_id]
        record["logs"] = [
            *record["logs"],
            {
                "time": display_time(),
                "level": level,
                "message": message,
            },
        ][-12:]


def update_scan(scan_id, **changes):
    with store_lock:
        record = scan_store[scan_id]
        record.update(changes)
        return dict(record)


def public_scan_summary(record):
    results = record.get("results") or {}
    summary = results.get("summary", {})
    return {
        "id": record["id"],
        "targetUrl": record["targetUrl"],
        "scanType": record["scanType"],
        "status": record["status"],
        "progress": record["progress"],
        "stage": record["stage"],
        "createdAt": record["createdAt"],
        "summary": summary,
    }


def public_status(record):
    return {
        "id": record["id"],
        "status": record["status"],
        "progress": record["progress"],
        "stage": record["stage"],
        "logs": record["logs"],
    }


def public_results(record):
    if record.get("results") is not None:
        return record["results"]

    return {
        "id": record["id"],
        "targetUrl": record["targetUrl"],
        "scanType": record["scanType"],
        "status": record["status"],
        "progress": record["progress"],
        "stage": record["stage"],
        "summary": summarize_findings([]),
        "findings": [],
        "owaspMappings": [],
    }


def public_report(record):
    if record.get("report") is not None:
        return record["report"]

    return {
        "id": record["id"],
        "generatedAt": record["createdAt"],
        "format": "PDF + JSON",
        "size": "Pending",
        "scope": record["targetUrl"],
        "summary": "Report will be available after the scan completes.",
        "artifacts": [
            {"label": "Executive summary", "detail": "Pending scan completion."},
            {"label": "Technical appendix", "detail": "Pending scan completion."},
            {"label": "JSON export", "detail": "Saved in the Hackathon report store."},
        ],
    }


def wrap_pdf_lines(lines, width=88):
    wrapped = []
    for line in lines:
        pieces = textwrap.wrap(line, width=width) or [""]
        wrapped.extend(pieces)
    return wrapped


def escape_pdf_text(value):
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(report, results):
    lines = [
        "AllScan Report",
        f"Target: {results['targetUrl']}",
        f"Scan Type: {results['scanType']}",
        f"Generated At: {report['generatedAt']}",
        f"Risk Score: {results['summary']['riskScore']}/100",
        "",
        "Findings:",
    ]

    findings = results.get("findings", [])
    if not findings:
        lines.append("No findings were detected.")
    else:
        for finding in findings:
            lines.append(
                f"- {finding['severity']} | {finding['type']} | {finding['url']} | {finding['parameter']}"
            )

    wrapped_lines = wrap_pdf_lines(lines)
    y = 760
    content_lines = ["BT", "/F1 12 Tf"]
    for line in wrapped_lines:
        content_lines.append(f"1 0 0 1 50 {y} Tm ({escape_pdf_text(line)}) Tj")
        y -= 16
        if y < 60:
            break
    content_lines.append("ET")
    content = "\n".join(content_lines)
    content_bytes = content.encode("latin-1", errors="replace")

    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        (
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj"
        ),
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(content_bytes)} >> stream\n{content}\nendstream\nendobj",
    ]

    pdf_parts = ["%PDF-1.4\n"]
    offsets = [0]
    current = len(pdf_parts[0].encode("latin-1"))

    for obj in objects:
        offsets.append(current)
        obj_text = f"{obj}\n"
        pdf_parts.append(obj_text)
        current += len(obj_text.encode("latin-1"))

    xref_offset = current
    pdf_parts.append(f"xref\n0 {len(offsets)}\n")
    pdf_parts.append("0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf_parts.append(f"{offset:010} 00000 n \n")
    pdf_parts.append(
        f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    )
    return "".join(pdf_parts).encode("latin-1", errors="replace")


def run_scan(scan_id, target_url, scan_type, selected_checks):
    try:
        update_scan(scan_id, status="running", progress=10, stage=PROGRESS_STAGES[1])
        append_log(scan_id, "info", "Crawler started.")

        crawler = Crawler(target_url, max_depth=resolve_depth(scan_type))
        discovered = crawler.crawl()
        manual_targets = build_manual_targets(target_url)
        all_targets = discovered + manual_targets

        append_log(scan_id, "info", f"Collected {len(all_targets)} candidate endpoints.")
        update_scan(scan_id, progress=45, stage=PROGRESS_STAGES[2])

        report_path = scan_report_path(scan_id)
        orchestrator = ScanOrchestrator(
            target_url,
            check_functions=selected_checks,
            report_path=report_path,
        )

        append_log(scan_id, "info", "Active checks started.")
        update_scan(scan_id, progress=75, stage=PROGRESS_STAGES[3])
        raw_report = orchestrator.run(all_targets)

        findings = [format_finding(item) for item in raw_report.get("findings", [])]
        summary = summarize_findings(findings)
        owasp_mappings = build_owasp_mappings(findings)
        generated_at = iso_now()

        results = {
            "id": scan_id,
            "targetUrl": target_url,
            "scanType": resolve_scan_type(scan_type),
            "status": "completed",
            "progress": 100,
            "stage": PROGRESS_STAGES[-1],
            "createdAt": get_scan_or_none(scan_id)["createdAt"],
            "summary": summary,
            "findings": findings,
            "owaspMappings": owasp_mappings,
        }

        report = {
            "id": scan_id,
            "generatedAt": generated_at,
            "format": "PDF + JSON",
            "size": f"{len(findings)} finding(s)",
            "scope": target_url,
            "summary": f"Scan completed with {len(findings)} finding(s).",
            "artifacts": [
                {"label": "Executive summary", "detail": "Risk score and severity overview."},
                {"label": "Technical appendix", "detail": "Per-finding URLs, parameters, and remediation."},
                {"label": "JSON export", "detail": os.path.basename(report_path)},
            ],
        }

        update_scan(
            scan_id,
            status="completed",
            progress=100,
            stage=PROGRESS_STAGES[-1],
            results=results,
            report=report,
        )
        append_log(scan_id, "success", f"Scan completed with {len(findings)} finding(s).")
    except Exception as error:
        update_scan(scan_id, status="failed", stage="Failed")
        append_log(scan_id, "error", f"Scan failed: {error}")


class AllScanApiHandler(BaseHTTPRequestHandler):
    server_version = "AllScanApi/1.0"

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        route = self.path.split("?", 1)[0]

        if route == "/api/scans":
            with store_lock:
                payload = [public_scan_summary(scan_store[scan_id]) for scan_id in scan_order]
            self.send_json(200, payload)
            return

        if route == "/api/health":
            self.send_json(200, {"status": "ok"})
            return

        scan_id, tail = self.parse_scan_route(route)
        if scan_id is None:
            self.send_json(404, {"message": "Route not found."})
            return

        record = get_scan_or_none(scan_id)
        if record is None:
            self.send_json(404, {"message": "Scan not found."})
            return

        if tail == "":
            self.send_json(200, public_scan_summary(record))
            return
        if tail == "/status":
            self.send_json(200, public_status(record))
            return
        if tail == "/results":
            self.send_json(200, public_results(record))
            return
        if tail == "/report":
            accept = self.headers.get("Accept", "")
            if "application/pdf" in accept:
                self.send_pdf(200, record["id"], build_pdf(public_report(record), public_results(record)))
                return
            self.send_json(200, public_report(record))
            return

        self.send_json(404, {"message": "Route not found."})

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route != "/api/scans":
            self.send_json(404, {"message": "Route not found."})
            return

        body = self.read_json_body()
        if body is None:
            return

        target_url = str(body.get("targetUrl", "")).strip()
        if not target_url:
            self.send_json(400, {"message": "targetUrl is required."})
            return

        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            self.send_json(400, {"message": "targetUrl must be a valid http/https URL."})
            return

        raw_checks = body.get("checks")
        checks = raw_checks if isinstance(raw_checks, list) else []
        selected_checks, unsupported_checks = resolve_checks(checks)
        scan_type = body.get("scanType", "deep")
        record = create_scan_record(target_url, scan_type, checks, unsupported_checks)

        worker = threading.Thread(
            target=run_scan,
            args=(record["id"], target_url, scan_type, selected_checks),
            daemon=True,
        )
        worker.start()

        self.send_json(
            201,
            {
                "id": record["id"],
                "targetUrl": record["targetUrl"],
                "scanType": record["scanType"],
                "checks": record["requestedChecks"],
                "status": record["status"],
                "progress": record["progress"],
                "stage": record["stage"],
                "createdAt": record["createdAt"],
            },
        )

    def read_json_body(self):
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self.send_json(400, {"message": "Invalid Content-Length header."})
            return None

        raw_body = self.rfile.read(length) if length > 0 else b""
        if not raw_body:
            return {}

        try:
            return json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_json(400, {"message": "Request body must be valid JSON."})
            return None

    def parse_scan_route(self, route):
        prefix = "/api/scans/"
        if not route.startswith(prefix):
            return None, None

        tail = route[len(prefix):]
        if not tail:
            return None, None

        parts = tail.split("/", 1)
        scan_id = parts[0]
        suffix = "" if len(parts) == 1 else f"/{parts[1]}"
        return scan_id, suffix

    def send_json(self, status_code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_pdf(self, status_code, scan_id, payload):
        filename = f"scan-{scan_id}.pdf"
        self.send_response(status_code)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), AllScanApiHandler)
    print(f"[*] AllScan API listening on http://{HOST}:{PORT}")
    server.serve_forever()
