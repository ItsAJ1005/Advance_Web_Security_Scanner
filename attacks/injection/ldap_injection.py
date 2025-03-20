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
        # More precise and targeted payloads
        self.payloads = [
            # Basic wildcard and filter manipulation
            "*)(cn=admin)",
            "*)(uid=admin)",
            "*)(&(uid=*)(cn=*))",
            "*)(|(uid=*)(cn=*))",
            
            # # Attribute enumeration attempts
            # "*)(objectClass=*)",
            # "*)(memberOf=admin)",
            
            # # Complex filter breaking
            # "*)((uid=*)(cn=*))",
            # "*)(|(objectClass=user)(cn=admin))",
            
            # # Potential information disclosure
            # "*)(|(description=*)(cn=*))",
            # "*)(mail=*)",
            
            # # Advanced injection patterns
            # "admin*",
            # "admin)(&)",
            # "*)(uid=admin)(uid=*)",
            # "*)((uid=admin))",
            
            # # Null byte and encoding tricks
            # "admin*))%00",
            # "admin*))\x00",
            
            # # Logical operator manipulation
            # "*)(|(uid=*)(&))",
            # "*)(|(&)(uid=*))"
        ]

    def scan(self) -> Dict:
        """
        Perform LDAP injection vulnerability scanning
        
        Returns:
            Dict of scan results with unique vulnerabilities
        """
        try:
            logging.info(f"Starting LDAP Injection scan on {self.target_url}")
            results = []
            unique_vulnerabilities = set()  # Track unique vulnerabilities
            
            # Prepare tasks for concurrent scanning
            tasks = []
            
            # Track processed input fields to avoid duplicates
            processed_inputs = set()
            
            # Test form inputs
            response = self.make_request(self.target_url)
            if response:
                forms = RequestUtils.extract_forms(response.text)
                for form in forms:
                    form_url = urljoin(self.target_url, form['action'] or self.target_url)
                    for input_field in form['inputs']:
                        # Skip if input field has already been processed
                        input_key = (form_url, input_field['name'])
                        
                        if input_field['type'] in ['text', 'password', 'search']:
                            # Use multiple payloads for each input field
                            for payload in self.payloads:
                                # Create a unique task key to prevent exact duplicates
                                task_key = (form_url, input_field['name'], payload)
                                
                                if task_key not in processed_inputs:
                                    tasks.append({
                                        'url': form_url,
                                        'method': form['method'],
                                        'input_name': input_field['name'],
                                        'payload': payload
                                    })
                                    
                                    # Mark this task as processed
                                    processed_inputs.add(task_key)
            
            # Test common endpoints and parameters
            test_endpoints = [
                '/ldap', '/login',
                #  '/auth', '/search', 
                # '/user', '/admin', '/directory', 
                # '/profile', '/account', '/', '/api/users'
            ]
            
            test_parameters = [
                'username',
                #  'user', 'query', 'q', 
                # 'search', 'id', 'uid', 'cn'
            ]
            
            for endpoint in test_endpoints:
                endpoint_url = urljoin(self.target_url, endpoint)
                for param in test_parameters:
                    for payload in self.payloads:
                        # Create a unique task key to prevent exact duplicates
                        task_key = (endpoint_url, param, payload)
                        
                        if task_key not in processed_inputs:
                            tasks.append({
                                'url': endpoint_url,
                                'method': 'GET',
                                'input_name': param,
                                'payload': payload
                            })
                            
                            # Mark this task as processed
                            processed_inputs.add(task_key)
            
            # Execute tasks
            for task in tasks:
                try:
                    # Prepare payload data
                    payload_data = {task['input_name']: task['payload']}
                    
                    # Make request with payload
                    response = self.make_request(
                        task['url'], 
                        method=task['method'], 
                        params=payload_data if task['method'] == 'GET' else None,
                        data=payload_data if task['method'] != 'GET' else None
                    )
                    
                    # Verify LDAP injection
                    if self.verify_ldap_injection(response, task['payload']):
                        # Create a unique vulnerability key
                        vuln_key = (task['url'], task['input_name'], task['payload'])
                        
                        # Add only if not already tracked
                        if vuln_key not in unique_vulnerabilities:
                            unique_vulnerabilities.add(vuln_key)
                            results.append({
                                'type': 'LDAP Injection',
                                'severity': 'High',
                                'url': task['url'],
                                'method': task['method'],
                                'input_name': task['input_name'],
                                'payload': task['payload'],
                                'evidence': f"LDAP injection detected with payload: {task['payload']}",
                                'details': 'The application appears vulnerable to LDAP injection attacks',
                                'recommendation': "\n".join([
                                    "1. Implement proper input validation",
                                    "2. Use LDAP search filters",
                                    "3. Escape special characters",
                                    "4. Use parameterized queries",
                                    "5. Implement least privilege access"
                                ])
                            })
                
                except Exception as e:
                    logging.error(f"Error during LDAP injection scan for {task['url']}: {e}")
            
            # Prepare final results
            scan_results = {
                'ldap_injection': results,
                'total_checked': len(tasks),
                'total_vulnerabilities': len(results)
            }
            
            logging.info(f"LDAP Injection scan completed. Found {len(results)} vulnerabilities.")
            return scan_results
        
        except Exception as e:
            logging.error(f"LDAP Injection scan failed: {e}", exc_info=True)
            return {
                'ldap_injection': [],
                'total_checked': 0,
                'total_vulnerabilities': 0,
                'error': str(e)
            }

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
        response_status = response.status_code
        
        # Strict injection detection indicators
        strict_indicators = [
            # Successful injection markers with context
            'cn=admin',           # Common Name admin exposure
            'uid=admin',          # User ID admin exposure
            'objectclass=user',   # User object class exposure
            'memberof=admin',     # Admin group membership
            
            # Specific LDAP error messages or information disclosure
            'ldap error',
            'invalid filter',
            'ldap filter syntax',
            'directory service error',
            'bind failed',
        ]
        
        # Payload-specific detection
        payload_indicators = [
            '*(', '*)', '*)(', 
            '(&', '(|', 
            'objectclass=', 
            'uid=', 'cn='
        ]
        
        # Detailed logging and console warning
        if (
            # Check for strict indicators
            any(indicator in response_text for indicator in strict_indicators) or
            
            # Check for payload-specific indicators with some context
            (any(indicator in response_text for indicator in payload_indicators) and 
             len(payload) > 1 and  # Ignore single character wildcards
             (response_status < 400 or  # Successful or redirected response
              response_status >= 500))  # Server error might indicate injection
        ):
            logging.warning(f"Potential LDAP Injection detected with payload: {payload}")
            return True
        
        return False
