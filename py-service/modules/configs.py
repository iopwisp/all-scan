import requests
import urllib.parse

def check_configs(endpoint):
    # Теперь принимаем словарь, как того требует engine.py
    url = endpoint.get("url")
    if not url: return None
    
    targets = {
        "/.env": ["DB_PASSWORD", "APP_SECRET", "SECRET_KEY"],
        "/.git/config": ["repositoryformatversion", "core"],
        "/phpinfo.php": ["PHP Version", "php.ini"]
    }
    
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for path, markers in targets.items():
        target_url = base_url + path
        try:
            # Таймаут 3 сек, чтобы не вешать сканер
            response = requests.get(target_url, timeout=3)
            if response.status_code == 200:
                for marker in markers:
                    if marker in response.text:
                        return {
                            "vuln_found": True,
                            "type": "Security Misconfiguration",
                            "severity": "HIGH",
                            "url": target_url,
                            "payload": path
                        }
        except: continue
    return {"vuln_found": False}