import logging
import re
import urllib.parse
from typing import Dict, Optional, List
from core.base_scanner import BaseScanner
import requests
import json

class SessionHijackingScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        
        # Comprehensive session vulnerability test scenarios
        self.session_tests = [
            # Session Token Predictability
            {
                'name': 'Predictable Session Token',
                'test_func': self.test_token_predictability,
                'severity': 'High',
                'http_method': 'POST',
                'vulnerable_parameter': 'session_token'
            },
            # Session Fixation
            {
                'name': 'Session Fixation',
                'test_func': self.test_session_fixation,
                'severity': 'Critical',
                'http_method': 'POST',
                'vulnerable_parameter': 'session_id'
            },
            # Concurrent Session Handling
            {
                'name': 'Concurrent Sessions',
                'test_func': self.test_concurrent_sessions,
                'severity': 'Medium',
                'http_method': 'POST',
                'vulnerable_parameter': 'session_management'
            }
        ]
        
        # Endpoints to test for session vulnerabilities
        self.session_endpoints = [
            '/login', 
            '/auth', 
            '/profile', 
            '/dashboard', 
            '/account',
            '/reset'
        ]

    def scan(self) -> Dict:
        """
        Perform comprehensive session hijacking vulnerability scanning
        
        Returns:
            Dict of detected vulnerabilities
        """
        logging.info(f"Starting Session Hijacking scan on {self.target_url}")
        vulnerabilities = []
        
        # Test base URL
        base_result = self.test_session_vulnerabilities(self.target_url)
        if base_result:
            vulnerabilities.extend(base_result)
        
        # Test additional session-related endpoints
        for endpoint in self.session_endpoints:
            full_url = self.target_url.rstrip('/') + endpoint
            endpoint_results = self.test_session_vulnerabilities(full_url)
            if endpoint_results:
                vulnerabilities.extend(endpoint_results)
        
        logging.info(f"Session Hijacking scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return {
            'session_hijacking': vulnerabilities
        } if vulnerabilities else {}

    def test_session_vulnerabilities(self, url: str) -> Optional[List[Dict]]:
        """
        Test a specific URL for session hijacking vulnerabilities
        
        Args:
            url (str): URL to test
        
        Returns:
            Optional list of vulnerability details
        """
        try:
            vulnerabilities = []
            
            # Run all session tests
            for test in self.session_tests:
                try:
                    result = test['test_func'](url)
                    if result:
                        vulnerability = {
                            'type': 'Session Hijacking',
                            'name': test['name'],
                            'url': url,
                            'severity': test['severity'],
                            'details': result,
                            'recommendation': self.get_recommendations(test['name']),
                            'method': test['http_method'],
                            'parameter': test['vulnerable_parameter'],
                            'payload': "None : No specific payload for session tests",  # No specific payload for session tests
                            'evidence': self.generate_evidence(result)
                        }
                        vulnerabilities.append(vulnerability)
                except Exception as test_error:
                    logging.error(f"Error in {test['name']} test: {test_error}")
            
            return vulnerabilities if vulnerabilities else None
        
        except Exception as e:
            logging.error(f"Error testing session vulnerabilities on {url}: {e}")
            return None

    def generate_evidence(self, details: str) -> str:
        """
        Generate additional evidence for the vulnerability
        
        Args:
            details (str): Vulnerability details
        
        Returns:
            Formatted evidence string
        """
        try:
            # Extract specific details about the vulnerability
            token_chars = self.analyze_token_characteristics(details)
            vuln_type = self.classify_vulnerability_type(details)
            
            # Create a formatted evidence string
            evidence = f"""
Vulnerability Type: {vuln_type}
Token Characteristics:
- Length: {token_chars['length']}
- Complexity: {token_chars['complexity']}
- Predictability: {token_chars['predictability']}

Detailed Analysis:
{details}
"""
            return evidence
        except Exception as e:
            logging.error(f"Error generating evidence: {e}")
            return "Unable to generate detailed evidence"

    def analyze_token_characteristics(self, details: str) -> Dict:
        """
        Analyze token characteristics based on vulnerability details
        
        Args:
            details (str): Vulnerability details
        
        Returns:
            Dict of token characteristics
        """
        characteristics = {
            'length': 'Unknown',
            'complexity': 'Low',
            'predictability': 'High'
        }
        
        # Specific analysis based on details
        if 'short' in details.lower():
            characteristics['length'] = 'Short'
        if 'numeric' in details.lower():
            characteristics['complexity'] = 'Very Low'
        if 'pattern' in details.lower():
            characteristics['predictability'] = 'Extremely High'
        
        return characteristics

    def classify_vulnerability_type(self, details: str) -> str:
        """
        Classify the specific type of session vulnerability
        
        Args:
            details (str): Vulnerability details
        
        Returns:
            Specific vulnerability classification
        """
        classifications = {
            'predictable': 'Weak Token Generation',
            'fixation': 'Session Fixation Vulnerability',
            'concurrent': 'Weak Session Management',
            'token': 'Insecure Session Token'
        }
        
        # Match details to specific classifications
        for key, classification in classifications.items():
            if key in details.lower():
                return classification
        
        return 'Generic Session Vulnerability'

    def test_token_predictability(self, url: str) -> Optional[str]:
        """
        Test for predictable session tokens
        
        Args:
            url (str): URL to test
        
        Returns:
            Vulnerability details or None
        """
        try:
            # Simulate login attempts to capture session tokens
            login_data = {'username': 'admin', 'password': 'admin123'}
            
            # First login attempt
            response1 = self.make_request(f"{url}/login", method='POST', data=login_data)
            
            # Second login attempt
            response2 = self.make_request(f"{url}/login", method='POST', data=login_data)
            
            if response1 and response2:
                # Compare session tokens
                tokens1 = {c.name: c.value for c in response1.cookies}
                tokens2 = {c.name: c.value for c in response2.cookies}
                
                for token_name, token_value in tokens1.items():
                    if token_name in tokens2 and tokens1[token_name] == tokens2[token_name]:
                        return f"Predictable session token detected for {token_name}. Tokens remain identical across login attempts, indicating weak token generation."
            
            return None
        
        except Exception as e:
            logging.error(f"Token predictability test error: {e}")
            return None

    def test_session_fixation(self, url: str) -> Optional[str]:
        """
        Test for session fixation vulnerability
        
        Args:
            url (str): URL to test
        
        Returns:
            Vulnerability details or None
        """
        try:
            # Initial request to get a session
            initial_resp = self.make_request(url)
            
            if initial_resp and initial_resp.cookies:
                # Capture initial session token
                initial_tokens = {c.name: c.value for c in initial_resp.cookies}
                
                # Simulate login
                login_data = {'username': 'admin', 'password': 'admin123'}
                login_resp = self.make_request(f"{url}/login", method='POST', data=login_data)
                
                if login_resp and login_resp.cookies:
                    post_login_tokens = {c.name: c.value for c in login_resp.cookies}
                    
                    # Check if any session tokens remain the same after login
                    for name, value in initial_tokens.items():
                        if name in post_login_tokens and value == post_login_tokens[name]:
                            return f"Session fixation vulnerability: Token {name} unchanged after login. Initial token persists post-authentication."
            
            return None
        
        except Exception as e:
            logging.error(f"Session fixation test error: {e}")
            return None

    def test_concurrent_sessions(self, url: str) -> Optional[str]:
        """
        Test if multiple simultaneous sessions are allowed
        
        Args:
            url (str): URL to test
        
        Returns:
            Vulnerability details or None
        """
        try:
            # Simulate two concurrent login attempts
            login_data = {'username': 'admin', 'password': 'admin123'}
            
            # First login
            session1 = self.make_request(f"{url}/login", method='POST', data=login_data)
            
            # Second login with same credentials
            session2 = self.make_request(f"{url}/login", method='POST', data=login_data)
            
            if session1 and session2 and session1.cookies and session2.cookies:
                # Check if both sessions are valid and different
                tokens1 = {c.name: c.value for c in session1.cookies}
                tokens2 = {c.name: c.value for c in session2.cookies}
                
                # If any token is the same, it might indicate poor session management
                for token_name in tokens1:
                    if token_name in tokens2 and tokens1[token_name] == tokens2[token_name]:
                        return "Multiple simultaneous sessions with identical tokens detected. Indicates weak session management and potential security risk."
            
            return None
        
        except Exception as e:
            logging.error(f"Concurrent sessions test error: {e}")
            return None

    def get_recommendations(self, vulnerability_type: str) -> str:
        """
        Generate recommendations based on vulnerability type
        
        Args:
            vulnerability_type (str): Type of session hijacking vulnerability
        
        Returns:
            Recommendations as a string
        """
        recommendations = {
            'Predictable Session Token': "\n".join([
                "1. Use cryptographically secure random token generation",
                "2. Implement session token rotation",
                "3. Use long, complex session identifiers",
                "4. Utilize libraries like secrets or uuid for token generation"
            ]),
            'Session Fixation': "\n".join([
                "1. Regenerate session ID after authentication",
                "2. Invalidate existing sessions on login",
                "3. Use secure session management libraries",
                "4. Implement strict session lifecycle management"
            ]),
            'Concurrent Sessions': "\n".join([
                "1. Implement strict session management",
                "2. Limit simultaneous sessions per user",
                "3. Use unique, non-predictable session tokens",
                "4. Implement session timeout and forced logout mechanisms"
            ])
        }
        
        return recommendations.get(vulnerability_type, "Follow general web security best practices")

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute a specific session hijacking task
        
        Args:
            task (Dict): Task configuration
        
        Returns:
            Optional vulnerability details
        """
        if task.get('type') == 'session_hijacking':
            return self.test_session_vulnerabilities(task.get('url', ''))
        
        return None
