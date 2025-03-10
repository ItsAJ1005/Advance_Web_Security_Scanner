from typing import Dict, List
import logging
import ssl
import socket
import requests
from urllib.parse import urlparse

class DefenseMechanism:
    def __init__(self):
        self.security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'Referrer-Policy'
        ]

    def analyze_security_headers(self, url: str) -> Dict:
        try:
            response = requests.get(url)
            missing_headers = []
            implemented_headers = []
            
            for header in self.security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
                else:
                    implemented_headers.append({
                        'header': header,
                        'value': response.headers[header]
                    })
            
            return {
                'missing_headers': missing_headers,
                'implemented_headers': implemented_headers
            }
        except Exception as e:
            logging.error(f"Error analyzing security headers: {e}")
            return {'error': str(e)}

    def check_ssl_tls(self, url: str) -> Dict:
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                'protocol_version': ssock.version(),
                'cipher': ssock.cipher(),
                'certificate': cert
            }
        except Exception as e:
            logging.error(f"Error checking SSL/TLS: {e}")
            return {'error': str(e)}
