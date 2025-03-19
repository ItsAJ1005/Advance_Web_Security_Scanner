# attacks/authentication/session_hijacking.py
import logging
from typing import Dict, Optional, List
from core.base_scanner import BaseScanner

class SessionHijackingScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.check_points = {
            'secure_flag': {
                'check': lambda c: not c.secure,
                'description': 'Cookie missing Secure flag'
            },
            'httponly_flag': {
                'check': lambda c: 'httponly' not in c._rest,
                'description': 'Cookie missing HttpOnly flag'
            },
            'samesite': {
                'check': lambda c: 'samesite' not in c._rest,
                'description': 'Cookie missing SameSite attribute'
            }
        }

    def scan(self) -> Dict:
        tasks = []
        response = self.make_request(self.target_url)
        
        if not response:
            return {"session_hijacking": []}

        # Check all cookies
        for cookie in response.cookies:
            tasks.append({
                'cookie_name': cookie.name,
                'cookie': cookie,
                'url': self.target_url
            })

        # Check common session endpoints
        session_endpoints = ['/login', '/auth', '/account', '/profile', '/dashboard']
        for endpoint in session_endpoints:
            resp = self.make_request(f"{self.target_url}{endpoint}")
            if resp:
                for cookie in resp.cookies:
                    tasks.append({
                        'cookie_name': cookie.name,
                        'cookie': cookie,
                        'url': f"{self.target_url}{endpoint}"
                    })

        results = self.run_concurrent_tasks(tasks)
        return {"session_hijacking": [r for r in results if r]}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Implement the required execute_task method"""
        try:
            cookie = task['cookie']
            vulnerabilities = []
            
            # Check for session-related cookies
            if any(term in cookie.name.lower() for term in ['sess', 'auth', 'token', 'id']):
                # Check cookie security attributes
                for check_name, check_info in self.check_points.items():
                    if check_info['check'](cookie):
                        vulnerabilities.append(check_info['description'])

                # Check if cookie is sent over HTTPS
                is_https = task['url'].startswith('https')
                if not is_https and not cookie.secure:
                    vulnerabilities.append('Cookie transmitted over unsecure HTTP')

                # Check cookie value characteristics
                cookie_value = cookie.value
                if len(cookie_value) < 16:
                    vulnerabilities.append('Session ID might be too short/predictable')
                
                if cookie_value.isalnum():
                    vulnerabilities.append('Session ID uses limited character set')

            if vulnerabilities:
                return {
                    'url': task['url'],
                    'cookie_name': task['cookie_name'],
                    'vulnerability': 'Session Hijacking Vulnerability',
                    'issues': vulnerabilities,
                    'severity': 'High',
                    'evidence': {
                        'cookie_name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': 'httponly' in cookie._rest,
                        'samesite': cookie._rest.get('samesite', 'None')
                    }
                }

            return None

        except Exception as e:
            logging.error(f"Error in session hijacking task: {e}")
            return None

    def test_session_security(self, url: str) -> List[Dict]:
        """Test session security implementation"""
        vulnerabilities = []
        
        # Test for session fixation
        initial_resp = self.make_request(url)
        if initial_resp and initial_resp.cookies:
            login_data = {'username': 'test', 'password': 'test'}
            login_resp = self.make_request(f"{url}/login", method='POST', data=login_data)
            
            if login_resp and login_resp.cookies:
                initial_cookies = {c.name: c.value for c in initial_resp.cookies}
                post_login_cookies = {c.name: c.value for c in login_resp.cookies}
                
                for name, value in initial_cookies.items():
                    if name in post_login_cookies and value == post_login_cookies[name]:
                        vulnerabilities.append({
                            'type': 'Session Fixation',
                            'detail': f'Session cookie {name} not changed after login'
                        })

        # Test for concurrent sessions
        if self.test_concurrent_sessions(url):
            vulnerabilities.append({
                'type': 'Concurrent Sessions',
                'detail': 'Multiple simultaneous sessions allowed'
            })

        return vulnerabilities

    def test_concurrent_sessions(self, url: str) -> bool:
        """Test if multiple simultaneous sessions are allowed"""
        try:
            # Create first session
            session1 = self.make_request(f"{url}/login", method='POST', 
                                       data={'username': 'test', 'password': 'test'})
            
            # Try creating second session
            session2 = self.make_request(f"{url}/login", method='POST',
                                       data={'username': 'test', 'password': 'test'})
            
            if session1 and session2 and session1.cookies and session2.cookies:
                # Check if both sessions are valid
                return True
                
        except Exception as e:
            logging.error(f"Error testing concurrent sessions: {e}")
        
        return False
