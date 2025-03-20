from core.scanner_imports import *
from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import Dict, List, Optional
import logging
from urllib.parse import urljoin
import re

class LDAPScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        # More comprehensive payloads
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
            ")(cn=*)))\x00",               # Binary null
            "*)(|(objectClass=*))",        # Object enumeration
            "*)(department=*)"             # Department enumeration
        ]

    def scan(self) -> Dict:
        """
        Perform LDAP injection vulnerability scanning
        
        Returns:
            Dict of scan results
        """
        try:
            logging.info(f"Starting LDAP Injection scan on {self.target_url}")
            results = []
            
            # Prepare tasks for concurrent scanning
            tasks = []
            
            # Test form inputs
            response = self.make_request(self.target_url)
            if response:
                forms = RequestUtils.extract_forms(response.text)
                for form in forms:
                    form_url = urljoin(self.target_url, form['action'] or self.target_url)
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'password', 'search']:
                            for payload in self.payloads:
                                tasks.append({
                                    'url': form_url,
                                    'method': form['method'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'type': 'form'
                                })
            
            # Test common endpoints
            test_endpoints = [
                '/ldap', '/login', '/auth', '/search', 
                '/user', '/admin', '/directory', 
                '/profile', '/account', '/', '/api/users'
            ]
            
            for endpoint in test_endpoints:
                endpoint_url = urljoin(self.target_url, endpoint)
                for param in ['username', 'user', 'query', 'q', 'search', 'id', 'uid']:
                    for payload in self.payloads:
                        tasks.append({
                            'url': endpoint_url,
                            'method': 'GET',
                            'parameter': param,
                            'payload': payload,
                            'type': 'endpoint'
                        })
            
            # Run tasks concurrently
            concurrent_results = self.run_concurrent_tasks(tasks)
            
            # Process and format results
            for result in concurrent_results:
                if result:
                    results.append({
                        'type': 'LDAP Injection',
                        'severity': 'High',
                        'url': result['url'],
                        'method': result['method'],
                        'parameter': result['parameter'],
                        'payload': result['payload'],
                        'evidence': f"LDAP injection detected with payload: {result['payload']}",
                        'details': 'The application appears vulnerable to LDAP injection attacks',
                        'recommendation': "\n".join([
                            "1. Implement proper input validation",
                            "2. Use LDAP search filters",
                            "3. Escape special characters",
                            "4. Use parameterized queries",
                            "5. Implement least privilege access"
                        ])
                    })
            
            logging.info(f"LDAP Injection scan completed. Found {len(results)} vulnerabilities.")
            return {'ldap_injection': results}
        
        except Exception as e:
            logging.error(f"LDAP scanner error: {e}", exc_info=True)
            return {'ldap_injection': []}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute LDAP injection test for a specific task
        
        Args:
            task (Dict): Task configuration for injection testing
        
        Returns:
            Optional vulnerability details
        """
        try:
            # Prepare request parameters
            params = {task['parameter']: task['payload']} if task['method'] == 'GET' else {}
            data = {task['parameter']: task['payload']} if task['method'] == 'POST' else {}
            
            # Make request
            response = self.make_request(
                task['url'], 
                method=task['method'], 
                params=params, 
                data=data
            )
            
            # Check for injection indicators
            if response and self.verify_ldap_injection(response, task['payload']):
                return task
            
            return None
        
        except Exception as e:
            logging.error(f"LDAP injection test error: {e}")
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
        
        # Detailed logging and console warning
        if any(indicator in response_text for indicator in injection_indicators):
            logging.warning(f"LDAP Injection detected with payload: {payload}")
            return True
        
        return False
