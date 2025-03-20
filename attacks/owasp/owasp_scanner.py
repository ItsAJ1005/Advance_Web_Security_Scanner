from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import Dict, List
import logging
import re
import traceback
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

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
        
        try:
            # Initial request to get base information
            initial_response = self.make_request(self.target_url)
            if not initial_response:
                logging.error(f"Failed to fetch initial response for {self.target_url}")
                return {'owasp_top_10': []}

            # Add debug logging
            logging.info(f"Initial response status: {initial_response.status_code}")
            logging.info(f"Initial response headers: {initial_response.headers}")
            logging.info(f"Initial response content length: {len(initial_response.text)}")

            # Run all vulnerability checks
            for vuln_type, check_function in self.vulnerabilities.items():
                try:
                    vuln_results = check_function(initial_response)
                    logging.info(f"{vuln_type} check results: {vuln_results}")
                    if vuln_results:
                        results.extend(vuln_results)
                except Exception as e:
                    logging.error(f"Error in {vuln_type} check: {e}")
                    logging.error(traceback.format_exc())
        
        except Exception as e:
            logging.error(f"Unexpected error in OWASP scanner: {e}")
            logging.error(traceback.format_exc())
        
        # Add debug logging for final results
        logging.info(f"Total OWASP vulnerabilities found: {len(results)}")
        
        return {'owasp_top_10': results}

    def check_injection(self, response) -> List[Dict]:
        results = []
        
        # SQL Injection error patterns
        sql_errors = [
            "SQL syntax.*MySQL", "Warning.*mysql_.*",
            "PostgreSQL.*ERROR", "Warning.*pg_.*",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Microsoft SQL Server", "SQLITE_ERROR"
        ]
        
        # Check response for SQL error patterns
        for error in sql_errors:
            if re.search(error, response.text, re.I):
                results.append({
                    'vulnerability': 'Injection',
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'url': self.target_url,
                    'details': f'SQL error pattern found: {error}',
                    'recommendation': 'Use parameterized queries, prepared statements, and input validation.'
                })
        
        # Test potential injection points
        forms = RequestUtils.extract_forms(response.text)
        for form in forms:
            for input_field in form.get('inputs', []):
                if input_field.get('type') not in ['submit', 'hidden', 'file']:
                    results.append({
                        'vulnerability': 'Injection',
                        'type': 'Potential Injection Point',
                        'severity': 'Medium',
                        'url': urljoin(self.target_url, form.get('action', '')),
                        'parameter': input_field.get('name'),
                        'details': f'Unsanitized input field: {input_field.get("name")}',
                        'recommendation': 'Implement strict input validation and sanitization.'
                    })
        
        return results

    def check_broken_auth(self, response) -> List[Dict]:
        results = []
        
        # Check for weak authentication indicators
        weak_indicators = [
            'login', 'signin', 'authentication', 'session'
        ]
        
        # Check for login forms without HTTPS
        forms = RequestUtils.extract_forms(response.text)
        for form in forms:
            form_url = urljoin(self.target_url, form.get('action', ''))
            if not form_url.startswith('https://'):
                results.append({
                    'vulnerability': 'Broken Authentication',
                    'type': 'Insecure Login Form',
                    'severity': 'High',
                    'url': form_url,
                    'details': 'Login form not served over HTTPS',
                    'recommendation': 'Enforce HTTPS for all authentication endpoints.'
                })
        
        # Check cookies
        for cookie in response.cookies:
            if not cookie.secure or 'httponly' not in str(cookie).lower():
                results.append({
                    'vulnerability': 'Broken Authentication',
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'url': self.target_url,
                    'details': f'Insecure cookie: {cookie.name}',
                    'recommendation': 'Set Secure and HttpOnly flags for all cookies.'
                })
        
        return results

    def check_sensitive_data(self, response) -> List[Dict]:
        results = []
        
        # Sensitive data patterns
        patterns = {
            'Credit Card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'API Key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, response.text)
            if matches:
                results.append({
                    'vulnerability': 'Sensitive Data Exposure',
                    'type': f'{pattern_name} Exposure',
                    'severity': 'High',
                    'url': self.target_url,
                    'details': f'Found {len(matches)} potential {pattern_name.lower()} matches',
                    'recommendation': 'Remove sensitive data from responses, use encryption and masking.'
                })
        
        return results

    def check_xss(self, response) -> List[Dict]:
        results = []
        
        # XSS test payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(document.domain)</script>",
            "<svg/onload=alert('XSS')>"
        ]
        
        # Check forms for potential XSS
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            for input_field in form.find_all(['input', 'textarea']):
                if input_field.get('type') not in ['hidden', 'submit', 'button']:
                    results.append({
                        'vulnerability': 'Cross-Site Scripting (XSS)',
                        'type': 'Potential Form-based XSS',
                        'severity': 'Medium',
                        'url': self.target_url,
                        'parameter': input_field.get('name'),
                        'details': f'Unsanitized input field: {input_field.get("name")}',
                        'recommendation': 'Implement input validation, output encoding, and Content Security Policy (CSP).'
                    })
        
        # Test XSS on URL parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            for payload in xss_payloads:
                test_url = f"{self.target_url}?test={payload}"
                test_response = self.make_request(test_url)
                
                if test_response and payload in test_response.text:
                    results.append({
                        'vulnerability': 'Cross-Site Scripting (XSS)',
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'url': test_url,
                        'payload': payload,
                        'details': f'XSS payload was reflected: {payload}',
                        'recommendation': 'Implement strict input validation and output encoding.'
                    })
        
        return results

    def check_security_misconfig(self, response) -> List[Dict]:
        results = []
        
        # Security headers to check
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (protect against clickjacking)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (prevent MIME type sniffing)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'Strict-Transport-Security': 'Missing HTTP Strict Transport Security (HSTS) header'
        }
        
        for header, message in security_headers.items():
            if header.lower() not in [h.lower() for h in response.headers]:
                results.append({
                    'vulnerability': 'Security Misconfiguration',
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'url': self.target_url,
                    'details': message,
                    'recommendation': f'Add {header} header to improve security.'
                })
        
        return results

    def check_xxe(self, response) -> List[Dict]:
        # Placeholder for XXE vulnerability check
        return []

    def check_broken_access(self, response) -> List[Dict]:
        # Placeholder for Broken Access Control check
        return []

    def check_insecure_deserialization(self, response) -> List[Dict]:
        # Placeholder for Insecure Deserialization check
        return []

    def check_vulnerable_components(self, response) -> List[Dict]:
        # Placeholder for Vulnerable and Outdated Components check
        return []

    def check_insufficient_logging(self, response) -> List[Dict]:
        # Placeholder for Insufficient Logging & Monitoring check
        return []
