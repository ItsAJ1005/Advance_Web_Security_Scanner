from attacks.owasp.zap_scanner import run_zap_scan

# Test URLs
test_urls = [
    'https://example.com',
    'https://www.google.com',
    'https://github.com'
]

for url in test_urls:
    print(f"\n--- Scanning {url} ---")
    results = run_zap_scan(url)
    print(results)
