from core.base_scanner import BaseScanner
from typing import Dict, List
import logging
import re
from urllib.parse import urljoin

class OWASPScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.vulnerabilities = {
            'injection': self.check_injection,
            'broken_auth': self.check_broken_auth,
            'sensitive_data': self.check_sensitive_data,
            'xxe': self.check_xxe,
            'broken_access': self.check_broken_access,
            'security_misconfig': self.check_security_misconfig,
            'xss': self.check_xss,
            'insecure_deserialization': self.check_insecure_deserialization,
            'components': self.check_vulnerable_components,
            'insufficient_logging': self.check_insufficient_logging
        }

    def scan(self) -> Dict:
        results = []
        
        for vuln_type, check_function in self.vulnerabilities.items():
            try:
                vuln_results = check_function()
                if vuln_results:
                    results.extend(vuln_results)
            except Exception as e:
                logging.error(f"Error checking {vuln_type}: {e}")
        
        return {'owasp_top_10': results}

    def check_injection(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check for SQL Injection indicators
        sql_errors = [
            "SQL syntax.*MySQL", "Warning.*mysql_.*",
            "PostgreSQL.*ERROR", "Warning.*pg_.*",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Microsoft SQL Server"
        ]
        
        for error in sql_errors:
            if re.search(error, response.text, re.I):
                results.append({
                    'vulnerability': 'Injection',
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'url': self.target_url,
                    'details': f'SQL error pattern found: {error}'
                })

        return results

    def check_broken_auth(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check for secure session cookies
        for cookie in response.cookies:
            if not cookie.secure or 'httponly' not in cookie._rest:
                results.append({
                    'vulnerability': 'Broken Authentication',
                    'type': 'Insecure Cookie Configuration',
                    'severity': 'Medium',
                    'url': self.target_url,
                    'details': f'Cookie {cookie.name} is not properly secured'
                })

        return results

    def check_sensitive_data(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check for sensitive data patterns
        patterns = {
            'Credit Card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'API Key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }

        for pattern_name, pattern in patterns.items():
            if re.search(pattern, response.text):
                results.append({
                    'vulnerability': 'Sensitive Data Exposure',
                    'type': f'{pattern_name} Exposed',
                    'severity': 'High',
                    'url': self.target_url,
                    'details': f'Found potential {pattern_name.lower()} in response'
                })

        return results

    # ... Add other OWASP Top 10 checks ...
    def check_xxe(self) -> List[Dict]:
        # Implementation for XXE vulnerability check
        return []

    def check_broken_access(self) -> List[Dict]:
        # Implementation for Broken Access Control check
        return []

    def check_security_misconfig(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check security headers
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'Strict-Transport-Security': 'Missing HSTS header'
        }

        for header, message in security_headers.items():
            if header not in response.headers:
                results.append({
                    'vulnerability': 'Security Misconfiguration',
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'url': self.target_url,
                    'details': message
                })

        return results

    def check_xss(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check for XSS vulnerabilities
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        # Check response for reflected content
        for payload in test_payloads:
            test_url = f"{self.target_url}?q={payload}"
            test_response = self.make_request(test_url)
            
            if test_response and payload in test_response.text:
                results.append({
                    'vulnerability': 'Cross-Site Scripting (XSS)',
                    'type': 'Reflected XSS',
                    'severity': 'High',
                    'url': test_url,
                    'details': f'XSS payload was reflected: {payload}'
                })

        # Check forms for potential XSS
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            for input_field in form.find_all(['input', 'textarea']):
                if input_field.get('type') not in ['hidden', 'submit', 'button']:
                    results.append({
                        'vulnerability': 'Cross-Site Scripting (XSS)',
                        'type': 'Potential Form-based XSS',
                        'severity': 'Medium',
                        'url': self.target_url,
                        'details': f'Unsanitized input field found: {input_field.get("name")}'
                    })

        return results

    def check_insecure_deserialization(self) -> List[Dict]:
        results = []
        # Check for common serialization endpoints
        endpoints = ['/api/data', '/deserialize', '/object']
        
        test_payload = 'O:8:"stdClass":0:{}'  # PHP object injection test
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.make_request(url, method='POST', data={'data': test_payload})
            
            if response and any(err in response.text.lower() for err in ['unserialize', 'deserialize']):
                results.append({
                    'vulnerability': 'Insecure Deserialization',
                    'type': 'Potential Object Injection',
                    'severity': 'High',
                    'url': url,
                    'details': 'Endpoint appears vulnerable to insecure deserialization'
                })
        
        return results

    def check_vulnerable_components(self) -> List[Dict]:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return []

        # Check for common vulnerable component signatures
        vulnerable_components = {
            'jquery-1.': 'jQuery 1.x (Outdated)',
            'bootstrap.min.js v2': 'Bootstrap 2.x (Outdated)',
            'angular.js/1.': 'AngularJS 1.x (Outdated)',
            'symfony/2.': 'Symfony 2.x (Outdated)'
        }

        for signature, component in vulnerable_components.items():
            if signature in response.text:
                results.append({
                    'vulnerability': 'Using Components with Known Vulnerabilities',
                    'type': 'Outdated Component',
                    'severity': 'Medium',
                    'url': self.target_url,
                    'details': f'Detected {component}'
                })

        return results

    def check_insufficient_logging(self) -> List[Dict]:
        results = []
        sensitive_endpoints = ['/login', '/admin', '/api/users', '/checkout']
        
        for endpoint in sensitive_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.make_request(url)
            
            if response and response.status_code != 404:
                results.append({
                    'vulnerability': 'Insufficient Logging & Monitoring',
                    'type': 'Sensitive Endpoint Without Proper Logging',
                    'severity': 'Medium',
                    'url': url,
                    'details': 'Sensitive endpoint should implement proper logging'
                })

        return results
