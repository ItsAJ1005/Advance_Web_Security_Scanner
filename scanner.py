import argparse
import json
import logging
import os
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor
from core.base_scanner import BaseScanner
from attacks.injection.sql_injection import SQLInjectionScanner
from attacks.xss.xss_scanner import XSSScanner

def load_config(config_path: str = "config/scanner_config.json") -> Dict:
    default_config = {
        "max_threads": 5,
        "request_delay": 0.5,
        "timeout": 30,
        "user_agent": "Security-Scanner-v1.0"
    }
    
    try:
        if os.path.exists(config_path):
            with open(config_path) as f:
                return {**default_config, **json.load(f)}
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
    return default_config

def save_results(results: Dict, output_path: str = "results/scan_results.json"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {output_path}")
    except Exception as e:
        logging.error(f"Failed to save results: {e}")

def setup_logging():
    os.makedirs('results', exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('results/scanner.log'),
            logging.StreamHandler()
        ]
    )

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--config", default="config/scanner_config.json", 
                      help="Path to configuration file")
    parser.add_argument("--output", default="results/scan_results.json",
                      help="Path to output results file")
    args = parser.parse_args()

    setup_logging()
    logging.info(f"Starting scan of {args.url}")

    config = load_config(args.config)
    results = {}

    # Create scanner instances
    scanners = [
        SQLInjectionScanner(args.url, config),
        XSSScanner(args.url, config)
    ]
    
    # Run scanners
    with ThreadPoolExecutor(max_workers=config.get('max_threads', 5)) as executor:
        future_to_scanner = {
            executor.submit(scanner.scan): scanner.__class__.__name__
            for scanner in scanners
        }
        
        for future in future_to_scanner:
            scanner_name = future_to_scanner[future]
            try:
                scan_result = future.result()
                results[scanner_name] = scan_result
                logging.info(f"Completed {scanner_name} scan")
            except Exception as e:
                logging.error(f"Scanner {scanner_name} failed: {e}")
                results[scanner_name] = {"error": str(e)}
    
    save_results(results, args.output)
    logging.info(f"Scan completed. Results saved to {args.output}")

if __name__ == "__main__":
    main()

# attacks/xss/xss_scanner.py
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
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

    def scan(self) -> Dict:
        results = []
        response = self.make_request(self.target_url)
        
        if not response:
            return {'xss': []}
            
        forms = RequestUtils.extract_forms(response.text)
        
        for form in forms:
            form_url = urljoin(self.target_url, form['action'] or self.target_url)
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'image']:
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
        
        return {'xss': results}

    def test_xss(self, url: str, method: str, param: str, payload: str) -> bool:
        try:
            data = {param: payload}
            response = self.make_request(
                url,
                method=method.upper(),
                data=data if method.lower() == 'post' else None,
                params=data if method.lower() == 'get' else None
            )
            
            if response and payload in response.text:
                logging.info(f"Found XSS vulnerability at {url} with parameter {param}")
                return True
                
            return False
        except Exception as e:
            logging.error(f"Error testing XSS: {e}")
            return False