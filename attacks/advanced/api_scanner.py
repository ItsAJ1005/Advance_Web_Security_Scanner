from core.base_scanner import BaseScanner
from typing import Dict, List, Optional
import json
import logging

class APISecurityScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.endpoints = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/swagger',
            '/docs',
            '/graphql'
        ]
        
    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Implementation of required execute_task method"""
        try:
            if task['type'] == 'endpoint':
                response = self.make_request(
                    task['url'],
                    method=task['method'],
                    headers={'Accept': 'application/json'}
                )
                
                if response:
                    # Check for common API vulnerabilities
                    vulnerabilities = []
                    
                    # Check for exposed documentation
                    if any(doc in response.text.lower() for doc in ['swagger', 'openapi', 'api-docs']):
                        vulnerabilities.append({
                            'type': 'Exposed API Documentation',
                            'severity': 'Medium',
                            'evidence': 'API documentation publicly accessible'
                        })
                    
                    # Check for sensitive data exposure
                    sensitive_patterns = ['password', 'token', 'key', 'secret', 'credential']
                    if any(pattern in response.text.lower() for pattern in sensitive_patterns):
                        vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'High',
                            'evidence': 'Sensitive information found in API response'
                        })
                    
                    if vulnerabilities:
                        return {
                            'url': task['url'],
                            'method': task['method'],
                            'vulnerabilities': vulnerabilities
                        }
            
            return None

        except Exception as e:
            logging.error(f"Error in API security task: {e}")
            return None

    def scan(self) -> Dict:
        tasks = []
        
        # Test common API endpoints
        for endpoint in self.endpoints:
            full_url = f"{self.target_url.rstrip('/')}{endpoint}"
            tasks.append({
                'type': 'endpoint',
                'url': full_url,
                'method': 'GET'
            })
        
        results = self.run_concurrent_tasks(tasks)
        return {'api_security': [r for r in results if r]}

    def check_exposed_api_docs(self) -> bool:
        common_paths = [
            '/api-docs',
            '/swagger',
            '/swagger-ui.html',
            '/openapi.json'
        ]
        
        for path in common_paths:
            response = self.make_request(f"{self.target_url}{path}")
            if response and response.status_code == 200:
                return True
        return False

    def test_mass_assignment(self) -> bool:
        test_payload = {
            'username': 'test_user',
            'role': 'admin',
            'is_admin': True
        }
        
        response = self.make_request(
            f"{self.target_url}/api/users",
            method='POST',
            json=test_payload
        )
        
        return response and response.status_code in [200, 201]

    def test_broken_object_level_auth(self) -> bool:
        # Test accessing resources without proper authorization
        test_endpoints = [
            '/api/users/1',
            '/api/admin',
            '/api/reports'
        ]
        
        for endpoint in test_endpoints:
            response = self.make_request(f"{self.target_url}{endpoint}")
            if response and response.status_code == 200:
                return True
        return False
