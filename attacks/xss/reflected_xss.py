from core.base_scanner import BaseScanner
import re

class ReflectedXSSScanner(BaseScanner):
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.xss_payloads = self._load_payloads()

    def _load_payloads(self):
        with open('payloads/xss.txt', 'r') as f:
            return [payload.strip() for payload in f.readlines()]

    def scan(self):
        vulnerabilities = []
        
        for payload in self.xss_payloads:
            test_params = {'q': payload}
            
            response = self._send_request(
                method='GET', 
                params=test_params
            )

            if self._detect_xss(response, payload):
                vulnerability = {
                    'type': 'Reflected XSS',
                    'payload': payload,
                    'risk': 'High',
                    'description': f"XSS vulnerability detected with payload: {payload}"
                }
                vulnerabilities.append(vulnerability)

        self.save_results(vulnerabilities)
        return vulnerabilities

    def _detect_xss(self, response, payload):
        """Advanced XSS detection mechanism"""
        if response and payload in response.text:
            # Check for script execution context
            script_context_patterns = [
                r'<script[^>]*>{}'.format(re.escape(payload)),
                r'on\w+\s*=\s*[\'"]{}[\'"]'.format(re.escape(payload))
            ]
            
            return any(re.search(pattern, response.text, re.IGNORECASE) 
                       for pattern in script_context_patterns)
        return False