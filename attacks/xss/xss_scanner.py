from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import List, Dict
import logging
from urllib.parse import urljoin

class XSSScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "' onclick=alert('XSS')><a href='#",
            "<iframe onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"-alert('XSS')-\"",
            "';alert('XSS')//",
            "<ScRiPt>alert('XSS')</sCrIpT>"
        ]

    def scan(self) -> Dict:
        try:
            results = []
            response = self.make_request(self.target_url)
            
            if not response:
                return {'xss': []}
                
            forms = RequestUtils.extract_forms(response.text)
            for form in forms:
                form_url = urljoin(self.target_url, form['action'] or self.target_url)
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button', 'image', 'file']:
                        for payload in self.payloads:
                            if self.test_xss(form_url, form['method'], input_field['name'], payload):
                                results.append({
                                    'url': form_url,
                                    'method': form['method'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'vulnerability': 'Cross-Site Scripting (XSS)',
                                    'severity': 'Medium'
                                })
            
            query_params = self.extract_url_parameters(self.target_url)
            for param in query_params:
                for payload in self.payloads:
                    if self.test_xss(self.target_url, 'get', param, payload):
                        results.append({
                            'url': self.target_url,
                            'method': 'get',
                            'parameter': param,
                            'payload': payload,
                            'vulnerability': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium'
                        })
            
            return {'xss': results}
            
        except Exception as e:
            logging.error(f"XSS scanner error: {e}")
            return {'xss': [], 'error': str(e)}

    def test_xss(self, url: str, method: str, param: str, payload: str) -> bool:
        try:
            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None
            )
            
            if not response:
                return False
                
            if payload in response.text:
                if self.verify_xss_vulnerability(response.text, payload):
                    logging.info(f"Found XSS vulnerability at {url} with parameter {param}")
                    return True
                    
            return False
            
        except Exception as e:
            logging.error(f"Error testing XSS: {e}")
            return False

    def verify_xss_vulnerability(self, response_text: str, payload: str) -> bool:
        from html import escape
        return payload in response_text and escape(payload) not in response_text

    def extract_url_parameters(self, url: str) -> List[str]:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            return list(params.keys())
        except Exception:
            return []