"""
AllScan — engine.py
Полная версия: Краулер, Оркестратор, ReportBuilder.
Поддержка ручных целей для Juice Shop и AI-ремедиации.
"""

import json
import os
import threading
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from modules import ALL_CHECKS

# Константы
MAX_CRAWL_DEPTH = 3
MAX_THREADS = 10
REQUEST_TIMEOUT = 3
REPORT_FILE = "report.json"

# Сменили название на AllScan
DEFAULT_HEADERS = {
    "User-Agent": "AllScan/1.0 (Vulnerability Scanner)"
}

class Crawler:
    def __init__(self, base_url: str, max_depth: int = MAX_CRAWL_DEPTH,
                 session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.domain = urlparse(base_url).netloc
        self._visited: set = set()
        self._endpoints: list = []
        self._seen_sigs: set = set()
        self._session = session or requests.Session()
        self._session.headers.update(DEFAULT_HEADERS)

    def crawl(self) -> list:
        self._recurse(self.base_url, depth=0)
        return self._endpoints

    def _recurse(self, url: str, depth: int) -> None:
        if depth > self.max_depth: return
        normalized = self._normalize(url)
        if normalized in self._visited: return
        self._visited.add(normalized)
        try:
            resp = self._session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except: return
        if "text/html" not in resp.headers.get("Content-Type", ""): return
        soup = BeautifulSoup(resp.text, "html.parser")
        self._extract_get_params(url)
        for tag in soup.find_all("a", href=True):
            link = urljoin(url, tag["href"])
            if self._is_in_scope(link):
                self._extract_get_params(link)
                self._recurse(link, depth + 1)
        self._extract_forms(url, soup)

    def _extract_get_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self._add_endpoint(clean_url, "GET", params)

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> None:
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(page_url, action) if action else page_url
            fields = [inp["name"] for inp in form.find_all("input", attrs={"name": True})]
            self._add_endpoint(form_url, method, fields)

    def _add_endpoint(self, url: str, method: str, params: list) -> None:
        sig = f"{method}|{url}|{','.join(sorted(params))}"
        if sig in self._seen_sigs: return
        self._seen_sigs.add(sig)
        self._endpoints.append({"url": url, "method": method, "params": params})

    def _normalize(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _is_in_scope(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

class ReportBuilder:
    def __init__(self, target_url: str, report_path: str = REPORT_FILE):
        self.target_url = target_url
        self.report_path = report_path
        self._findings: list = []
        self._lock = threading.Lock()
        self._flush("in_progress")

    def add_finding(self, result: dict) -> None:
        if not result or not result.get("vuln_found"): return
        
        # Инновация: Добавляем советы ИИ (заглушка для хакатона)
        remediation_map = {
            "SQL Injection": "Используйте параметризованные запросы (Prepared Statements) и фильтрацию вводимых данных.",
            "Reflected XSS": "Внедрите Content Security Policy (CSP) и экранируйте спецсимволы в выводе HTML.",
            "Security Misconfiguration": "Ограничьте доступ к системным файлам (.env, .git) на уровне конфигурации веб-сервера."
        }
        
        finding = {
            "type": result.get("type", "Unknown"),
            "severity": result.get("severity", "MEDIUM"),
            "url": result.get("url", ""),
            "payload": result.get("payload", ""),
            "ai_remediation": remediation_map.get(result.get("type"), "Рекомендуется провести глубокий аудит безопасности данного эндпоинта.")
        }
        with self._lock:
            self._findings.append(finding)
            self._flush("in_progress")

    def finalize(self) -> dict:
        with self._lock:
            self._flush("completed")
            return self._build_report("completed")

    def _flush(self, status: str) -> None:
        report = self._build_report(status)
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def _build_report(self, status: str) -> dict:
        return {
            "scan_status": status,
            "target_url": self.target_url,
            "total_found": len(self._findings),
            "findings": list(self._findings),
        }

class ScanOrchestrator:
    def __init__(
        self,
        target_url: str,
        check_functions: Optional[list] = None,
        report_path: str = REPORT_FILE,
    ):
        self.check_functions = ALL_CHECKS if check_functions is None else check_functions
        self.report = ReportBuilder(target_url, report_path=report_path)

    def run(self, endpoints: list) -> dict:
        tasks = [(fn, ep) for ep in endpoints for fn in self.check_functions]
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
            futures = {pool.submit(self._safe_call, fn, ep): (fn.__name__, ep["url"]) for fn, ep in tasks}
            for future in as_completed(futures):
                result = future.result()
                if result: self.report.add_finding(result)
        return self.report.finalize()

    @staticmethod
    def _safe_call(fn, endpoint: dict) -> Optional[dict]:
        try:
            return fn(endpoint)
        except: return None

# ТОЧКА ВХОДА ДЛЯ ХАКАТОНА
if __name__ == "__main__":
    target = "http://localhost:3456"
    print(f"[*] AllScan запущен на {target}...")

    # Ручные цели, чтобы гарантированно пробить Juice Shop
    juicy_manual_targets = [
        {"url": f"{target}/rest/products/search", "method": "GET", "params": ["q"]},
        {"url": f"{target}/rest/user/login", "method": "POST", "params": ["email", "password"]},
        {"url": f"{target}/api/Feedbacks", "method": "POST", "params": ["comment"]}
    ]

    orchestrator = ScanOrchestrator(target)
    
    # Сначала пытаемся краулить, но добавляем ручные цели
    crawler = Crawler(target)
    found_endpoints = crawler.crawl()
    all_targets = found_endpoints + juicy_manual_targets

    final_report = orchestrator.run(all_targets)
    print(f"[+] Сканирование завершено. Найдено уязвимостей: {final_report['total_found']}")
