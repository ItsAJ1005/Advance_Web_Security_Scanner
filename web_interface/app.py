from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import logging
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue
import uuid
import time

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
from attacks.injection.ldap_injection import LDAPInjectionScanner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
scan_results = {}
active_scans = {}

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
                'sql_injection': SQLInjectionScanner,
                'xss': XSSScanner,
                'brute_force': BruteForceScanner,
                'ldap_injection': LDAPInjectionScanner,
            }
            
            total = len(self.selected_attacks)
            for i, attack in enumerate(self.selected_attacks, 1):
                try:
                    if attack in scanners:
                        self.current_attack = attack
                        scanner = scanners[attack](self.target_url, self.config)
                        result = scanner.scan()
                        
                        # Store results explicitly
                        if result and result.get(attack):
                            self.results[attack] = result[attack]
                            logging.info(f"Found vulnerabilities in {attack} scan")
                            
                        self.completed_attacks.append(attack)
                        self.progress = int((i / total) * 100)
                        logging.info(f"Progress: {self.progress}%")
                        
                except Exception as e:
                    logging.error(f"Error in {attack} scan: {e}")
                    self.results[attack] = []

            self.status = "completed"
            logging.info(f"Final results: {self.results}")
            
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            logging.error(f"Scan failed: {e}")

ATTACK_INFO = {
    'sql_injection': {
        'name': 'SQL Injection',
        'description': 'Tests for SQL injection vulnerabilities in input parameters and forms.',
        'severity': 'High',
        'owasp_category': 'A03:2021-Injection'
    },
    'xss': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Detects potential XSS vulnerabilities in web applications.',
        'severity': 'Medium',
        'owasp_category': 'A03:2021-Injection'
    },
    # Add other attacks info...
}

@app.route('/')
def index():
    return render_template('index.html', attack_info=ATTACK_INFO)

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    selected_attacks = request.form.getlist('attacks')
    
    if not target_url:
        return jsonify({'error': 'No target URL provided'}), 400

    # Ensure target URL has scheme
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    config = load_config()
    scan_task = ScanTask(target_url, selected_attacks, config)
    active_scans[scan_task.id] = scan_task
    
    thread = threading.Thread(target=scan_task.run)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_task.id})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    scan_task = active_scans.get(scan_id)
    if not scan_task:
        return jsonify({'error': 'Scan not found'}), 404
        
    response = {
        'status': scan_task.status,
        'progress': scan_task.progress,
        'current_attack': scan_task.current_attack,
        'completed_attacks': scan_task.completed_attacks,
        'results': None,
        'error': scan_task.error
    }
    
    if scan_task.status == 'completed':
        # Process and format results
        formatted_results = {}
        for attack_type, results in scan_task.results.items():
            # Handle dictionary results
            if isinstance(results, dict):
                if attack_type in results:
                    if results[attack_type]:  # Only include if there are findings
                        formatted_results[attack_type] = results[attack_type]
            # Handle list results
            elif isinstance(results, list) and results:
                formatted_results[attack_type] = results

        response['results'] = formatted_results if formatted_results else None
        logging.info(f"Scan results: {formatted_results}")
    
    return jsonify(response)

@app.route('/attack_info/<attack_type>')
def get_attack_info(attack_type):
    if attack_type in ATTACK_INFO:
        return jsonify(ATTACK_INFO[attack_type])
    return jsonify({'error': 'Attack type not found'}), 404

def load_config() -> Dict:
    config_path = os.path.join(parent_dir, 'config', 'scanner_config.json')
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {}

@app.route('/dashboard')
def dashboard():
    owasp_vulnerabilities = [
        {
            'id': 'injection',
            'name': 'Injection',
            'description': 'SQL, NoSQL, LDAP, and OS injection flaws',
            'details': 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.'
        },
        {
            'id': 'broken_auth',
            'name': 'Broken Authentication',
            'description': 'Authentication and session management flaws',
            'details': 'Application functions related to authentication and session management are often implemented incorrectly.'
        },
        # ... Add other OWASP top 10 vulnerabilities ...
    ]
    
    available_attacks = [
        {
            'id': 'sql_injection',
            'name': 'SQL Injection',
            'description': 'Tests for SQL injection vulnerabilities',
            'details': 'Attempts to inject malicious SQL queries.',
            'example': "' OR '1'='1"
        },
        {
            'id': 'xss',
            'name': 'Cross-Site Scripting',
            'description': 'Tests for XSS vulnerabilities',
            'details': 'Attempts to inject malicious scripts.',
            'example': "<script>alert('XSS')</script>"
        },
        # ... Add other available attacks ...
    ]
    
    return render_template('dashboard.html',
                         owasp_vulnerabilities=owasp_vulnerabilities,
                         available_attacks=available_attacks)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    url = data.get('url')
    scan_type = data.get('type')

    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    config = load_config()
    results = {}
    
    try:
        if (scan_type == 'full'):
            for scanner_class in ALL_SCANNERS:
                scanner = scanner_class(url, config)
                results.update(scanner.scan())
        elif (scan_type == 'owasp'):
            vuln_id = data.get('vulnId')
            if vuln_id in OWASP_SCANNERS:
                scanner = OWASP_SCANNERS[vuln_id](url, config)
                results.update(scanner.scan())
        elif (scan_type == 'single'):
            attack_id = data.get('attackId')
            if attack_id in SCANNERS_MAP:
                scanner = SCANNERS_MAP[attack_id](url, config)
                results.update(scanner.scan())
                
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

from tools.tool_integration import IntegratedScanner

# Add to your scan route
@app.route('/integrated_scan', methods=['POST'])
def integrated_scan():
    target_url = request.form.get('target_url')
    profile = request.form.get('profile', 'quick')
    
    if not target_url:
        return jsonify({'error': 'No target URL provided'}), 400

    scanner = IntegratedScanner()
    scan_task = ScanTask(target_url, ['integrated'], {})
    active_scans[scan_task.id] = scan_task
    
    def run_scan():
        try:
            results = scanner.run_integrated_scan(target_url, profile)
            scan_task.results = results
            scan_task.status = "completed"
        except Exception as e:
            scan_task.status = "failed"
            scan_task.error = str(e)

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_task.id})

if __name__ == '__main__':
    app.run(debug=True, port=8000)
