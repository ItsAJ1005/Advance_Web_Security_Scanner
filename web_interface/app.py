import logging

from attacks.access_control.idor import IDORScanner

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner_debug.log'),
        logging.StreamHandler()
    ]
)

from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import uuid
from typing import Dict, List  # Add List to imports

# Add parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from attacks.injection.sql_injection import SQLInjectionScanner
from attacks.xss.xss_scanner import XSSScanner
from attacks.injection.xxe_injection import XXEInjectionScanner
from attacks.authentication.session_hijacking import SessionHijackingScanner
from attacks.authentication.brute_force import BruteForceScanner
from attacks.advanced.ssrf import SSRFScanner
from attacks.advanced.api_scanner import APISecurityScanner
from attacks.owasp.owasp_scanner import OWASPScanner
from attacks.owasp.zap_scanner import run_zap_scan
from attacks.injection.command_injection import CommandInjectionScanner
from attacks.network.port_scanner import PortScanner
from attacks.injection.ldap_injection import LDAPScanner  # Add this import
from attacks.directory_fuzzing.directory_brute_forcer import DirectoryBruteForcer  # Fix import

app = Flask(__name__)

active_scans = {}

def load_config() -> Dict:
    """Load scanner configuration from JSON file"""
    config_path = os.path.join(parent_dir, 'config', 'scanner_config.json')
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {}

class ScanTask:
    def __init__(self, target_url: str, selected_attacks: List[str], config: Dict):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.selected_attacks = selected_attacks
        self.config = config
        self.status = "pending"
        self.progress = 0
        self.results = {}
        self.error = None
        self.current_attack = None
        self.completed_attacks = []

    def run(self):
        try:
            self.status = "running"
            scanners = {
                'sql_injection': ('SQL Injection', SQLInjectionScanner),
                'xss': ('Cross-Site Scripting', XSSScanner),
                'brute_force': ('Brute Force', BruteForceScanner),
                'session_hijacking': ('Session Hijacking', SessionHijackingScanner),
                'ssrf': ('SSRF', SSRFScanner),
                'api_security': ('API Security', APISecurityScanner),
                'owasp': ('OWASP Top 10', OWASPScanner),
                'command_injection': ('Command Injection', CommandInjectionScanner),
                'xxe_injection': ('XXE Injection', XXEInjectionScanner),
                'port_scan': ('Port Scan', PortScanner),
                'idor': ('IDOR', IDORScanner),
                'ldap_injection': ('LDAP Injection', LDAPScanner),  # Corrected LDAP scanner key
                'xxe': ('XXE Injection', XXEInjectionScanner),  # Make sure this exact key is used
                'dir_fuzzing': ('Directory Fuzzing', DirectoryBruteForcer),  # Add directory fuzzing
            }

            total = len(self.selected_attacks)
            for i, attack in enumerate(self.selected_attacks):
                if attack in scanners:
                    name, scanner_class = scanners[attack]
                    self.current_attack = name
                    logging.info(f"Starting {name} scan")  # Add debug logging

                    try:
                        scanner = scanner_class(self.target_url, self.config)
                        result = scanner.scan()
                        logging.info(f"Scan result for {name}: {result}")  # Add debug logging
                        
                        if result:
                            if attack == 'xxe':
                                self.results['xxe_injection'] = result.get('xxe_injection', [])
                                logging.info(f"XXE results processed: {self.results['xxe_injection']}")
                            else:
                                self.results[attack] = result

                        self.completed_attacks.append(name)
                        self.progress = int(((i + 1) / total) * 100)

                    except Exception as e:
                        logging.error(f"Error in {name}: {e}")
                        continue

            self.status = "completed"
            logging.info(f"Scan completed. Results: {self.results}")

        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            logging.error(f"Scan failed: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    selected_attacks = request.form.getlist('attacks')
    
    if not target_url:
        return jsonify({'error': 'No target URL provided'}), 400

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    config = load_config()
    scan_task = ScanTask(target_url, selected_attacks, config)
    active_scans[scan_task.id] = scan_task
    
    thread = threading.Thread(target=scan_task.run)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_task.id})

@app.route('/owasp-scan', methods=['POST'])
def owasp_scan():
    target_url = request.form.get('target_url')
    
    # Validate input
    if not target_url:
        return jsonify({
            'status': 'error', 
            'message': 'No target URL provided'
        }), 400
    
    # Ensure URL has protocol
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Logging for debugging
    app.logger.info(f"Starting OWASP scan for URL: {target_url}")
    
    try:
        # Run ZAP scan with extended timeout and error handling
        scan_results = run_zap_scan(target_url)
        
        # Log the results for debugging
        app.logger.info(f"Scan Results for {target_url}: {scan_results}")
        
        # Ensure results are returned even if empty
        return jsonify({
            'status': 'completed',
            'results': scan_results or {}
        })
    
    except Exception as e:
        # Detailed error logging
        app.logger.error(f"OWASP Scan Error for {target_url}: {str(e)}", exc_info=True)
        
        return jsonify({
            'status': 'failed',
            'error': str(e),
            'results': {}
        }), 500

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    scan_task = active_scans.get(scan_id)
    if not scan_task:
        return jsonify({'error': 'Scan not found'}), 404

    response = {
        'status': scan_task.status,
        'progress': '100' if scan_task.status == 'completed' else str(scan_task.progress),
        'current_attack': scan_task.current_attack,
        'completed_attacks': scan_task.completed_attacks,
        'results': None,
        'error': scan_task.error
    }

    if scan_task.status == 'completed':
        results = {}
        for attack_type, findings in scan_task.results.items():
            if isinstance(findings, dict) and attack_type in findings:
                results[attack_type] = findings[attack_type]
            elif isinstance(findings, list):
                results[attack_type] = findings
            
        response['results'] = results

    logging.info(f"Status update for scan {scan_id}: {response}")
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
