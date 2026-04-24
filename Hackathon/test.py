from modules import ALL_CHECKS

# Теперь передаем словарь, как это делает основной движок
target_endpoint = {
    "url": "http://localhost:3456/rest/products/search",
    "method": "GET",
    "params": ["q"]
}

print(f"[*] Тестируем AllScan на: {target_endpoint['url']}")

for check_func in ALL_CHECKS:
    result = check_func(target_endpoint)
    if result and result.get("vuln_found"):
        print(f"[!] УЯЗВИМОСТЬ: {result['type']} | Пейлоад: {result.get('payload')}")
    else:
        print(f"[-] {check_func.__name__} ничего не нашел.")