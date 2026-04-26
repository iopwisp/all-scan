import requests
import re

DB_ERRORS = {
    "MySQL": re.compile(r"SQL syntax.*MySQL|Warning.*mysql_.*", re.I),
    "PostgreSQL": re.compile(r"PostgreSQL.*ERROR|Warning.*\Wpg_.*", re.I),
    "Generic": re.compile(r"Syntax error in SQL statement|SQL error", re.I)
}

PAYLOADS = ["'", "' OR 1=1--", "') OR ('1'='1"]

def check_sqli(endpoint):
    url = endpoint.get("url")
    method = endpoint.get("method", "GET").upper()
    params = endpoint.get("params", [])
    
    if not params: return None

    for payload in PAYLOADS:
        # Для Juice Shop обязательно шлем JSON в POST
        test_data = {p: payload for p in params}
        try:
            if method == "POST":
                resp = requests.post(url, json=test_data, timeout=3)
            else:
                resp = requests.get(url, params=test_data, timeout=3)

            # Если видим ошибку БД или сервер выдал 500 на кавычку — это оно
            if resp.status_code == 500 or any(regex.search(resp.text) for regex in DB_ERRORS.values()):
                return {
                    "vuln_found": True,
                    "type": "SQL Injection",
                    "severity": "HIGH",
                    "url": url,
                    "payload": payload
                }
        except: continue
    return {"vuln_found": False}