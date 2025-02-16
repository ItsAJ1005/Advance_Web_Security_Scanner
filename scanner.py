import argparse
import json
import logging
import os
from typing import Dict
from concurrent.futures import ThreadPoolExecutor
from attacks.advanced.ssrf import SSRFScanner
from attacks.authentication.brute_force import BruteForceScanner
from attacks.authentication.session_hijacking import SessionHijackingScanner
from attacks.injection.xxe_injection import XXEInjectionScanner
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
    parser.add_argument("--config", default="config/scanner_config.json", help="Path to configuration file")
    parser.add_argument("--output", default="results/scan_results.json", help="Path to output results file")
    args = parser.parse_args()
    
    setup_logging()
    config = load_config(args.config)
    enabled_attacks = config.get("enabled_attacks", [])
    
    results = {}
    scanners = []
    
    if "sql_injection" in enabled_attacks:
        scanners.append(SQLInjectionScanner(args.url, config))
    if "xss" in enabled_attacks:
        scanners.append(XSSScanner(args.url, config))
    if "ssrf" in enabled_attacks:
        scanners.append(SSRFScanner(args.url, config))
    if "xxe_injection" in enabled_attacks:
        scanners.append(XXEInjectionScanner(args.url, config))
    if "brute_force" in enabled_attacks:
        scanners.append(BruteForceScanner(args.url, config))
    if "session_hijacking" in enabled_attacks:
        scanners.append(SessionHijackingScanner(args.url, config))
    # Add additional scanners here based on the enabled attacks
    #....ADD HERE
    #
    

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

if __name__ == '__main__':
    main()
