import time
import logging
import re  # Add this import
from typing import Dict, Optional
from core.base_scanner import BaseScanner

class BruteForceScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.login_url = target_url.rstrip('/') + "/login"
        self.credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("user", "password"),
            ("test", "test")
        ]
        self.request_delay = config.get("request_delay", 0.5)

    def scan(self) -> Dict:
        tasks = []
        
        # Create tasks for credential testing
        for username, password in self.credentials:
            tasks.append({
                'username': username,
                'password': password,
                'url': self.login_url
            })
            
        results = self.run_concurrent_tasks(tasks)
        return {'brute_force': [r for r in results if r]}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Implement the required execute_task method"""
        try:
            time.sleep(self.request_delay)  # Respect rate limiting
            username = task['username']
            password = task['password']
            
            data = {
                'username': username,
                'password': password
            }
            
            # First make a GET request to get any CSRF token if needed
            init_response = self.make_request(task['url'], method='GET')
            if init_response:
                # Look for CSRF token in response
                csrf_token = self.extract_csrf_token(init_response.text)
                if csrf_token:
                    data['csrf_token'] = csrf_token

            # Make login attempt
            response = self.make_request(
                task['url'],
                method='POST',
                data=data,
                allow_redirects=False  # Don't follow redirects to better detect success
            )

            if not response:
                return None

            # Check for successful login indicators
            success_indicators = [
                lambda r: r.status_code == 302,  # Redirect after successful login
                lambda r: 'welcome' in r.text.lower(),
                lambda r: 'dashboard' in r.text.lower(),
                lambda r: 'logout' in r.text.lower(),
                lambda r: 'success' in r.text.lower(),
                lambda r: any(c.name.lower() in ['session', 'auth', 'token'] 
                            for c in r.cookies)
            ]

            # Check for failed login indicators
            failure_indicators = [
                'invalid',
                'failed',
                'incorrect',
                'error',
                'wrong password'
            ]

            # If any success indicator is present and no failure indicators
            if (any(check(response) for check in success_indicators) and 
                not any(fail in response.text.lower() for fail in failure_indicators)):
                return {
                    'url': task['url'],
                    'username': username,
                    'password': password,
                    'type': 'Successful Brute Force',
                    'severity': 'High',
                    'evidence': {
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'cookies_set': bool(response.cookies)
                    }
                }

            return None

        except Exception as e:
            logging.error(f"Error in brute force task: {e}")
            return None

    def extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML content"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Search by common CSRF field names
            csrf_fields = [
                'csrf_token',
                'csrftoken',
                '_csrf',
                '_csrf_token',
                'authenticity_token'
            ]
            
            # Try finding by input field
            for field in csrf_fields:
                token_input = soup.find('input', attrs={'name': re.compile(field, re.I)})
                if token_input and token_input.get('value'):
                    return token_input['value']
            
            # Try finding in meta tags
            meta_token = soup.find('meta', attrs={'name': re.compile('csrf', re.I)})
            if meta_token:
                return meta_token.get('content')
                
            return None
            
        except Exception as e:
            logging.error(f"Error extracting CSRF token: {e}")
            return None
