import requests

def check_xss(endpoint):
    url = endpoint.get("url")
    method = endpoint.get("method", "GET").upper()
    params = endpoint.get("params", [])
    payload = "\"><script>console.log('XSS')</script>"
    
    if not params: return None

    for param in params:
        test_data = {p: payload if p == param else "test" for p in params}
        try:
            if method == "POST":
                resp = requests.post(url, json=test_data, timeout=3)
            else:
                resp = requests.get(url, params=test_data, timeout=3)

            if payload in resp.text:
                return {
                    "vuln_found": True,
                    "type": "Reflected XSS",
                    "severity": "MEDIUM",
                    "url": url,
                    "payload": payload
                }
        except: pass
    return None