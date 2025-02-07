from core.base_scanner import BaseScanner
import re
import base64

class SessionHijackingScanner(BaseScanner):
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.session_patterns = [
            r'PHPSESSID=(\w+)',
            r'session_token=([a-zA-Z0-9]+)',
            r'jwt=([a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)'
        ]

    def scan(self):
        vulnerabilities = []
        
        # Attempt to extract session tokens from multiple requests
        for endpoint in ['/login', '/dashboard', '/profile']:
            response = self._send_request(method='GET', path=endpoint)
            
            if response:
                session_vulnerabilities = self._analyze_session(response)
                vulnerabilities.extend(session_vulnerabilities)

        self.save_results(vulnerabilities)
        return vulnerabilities

    def _analyze_session(self, response):
        vulnerabilities = []
        
        # Extract session tokens
        for pattern in self.session_patterns:
            matches = re.findall(pattern, str(response.headers))
            
            for token in matches:
                # Check token predictability and information leakage
                if self._is_weak_token(token):
                    vulnerability = {
                        'type': 'Session Token Weakness',
                        'token': token,
                        'risk': 'High',
                        'description': f"Weak or predictable session token detected: {token}"
                    }
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_weak_token(self, token):
        """Analyze token strength"""
        # Check token length
        if len(token) < 16:
            return True
        
        # Check for sequential or predictable patterns
        try:
            # Decode base64 tokens to check for patterns
            decoded = base64.b64decode(token + '==')
            if len(set(decoded)) < len(decoded) * 0.5:
                return True
        except:
            pass

        return False