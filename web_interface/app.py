from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import logging
from concurrent.futures import ThreadPoolExecutor

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

app = Flask(__name__)

# Attack information dictionary
ATTACK_INFO = {
    'sql-injection': {
        'name': 'SQL Injection',
        'description': 'SQL injection is a code injection technique that might destroy your database.',
        'how_it_works': 'Attackers insert malicious SQL queries via input fields.',
        'vulnerabilities': [
            'Unsanitized input in SQL queries',
            'Direct use of user input in queries',
            'Improper error handling'
        ],
        'mitigations': [
            'Use prepared statements',
            'Input validation',
            'Proper error handling',
            'Least privilege principle'
        ],
        'references': [
            {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
        ],
        'has_options': True,
        'options': [
            {'value': 'error_based', 'label': 'Error-based Injection'},
            {'value': 'time_based', 'label': 'Time-based Injection'},
            {'value': 'boolean_based', 'label': 'Boolean-based Injection'}
        ]
    },
    # Add other attacks similarly
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack/<attack_type>')
def attack_module(attack_type):
    if attack_type in ATTACK_INFO:
        return render_template('attack_module.html', attack_info=ATTACK_INFO[attack_type])
    return "Attack module not found", 404

@app.route('/owasp-scan')
def owasp_scan():
    return render_template('owasp_scan.html')

@app.route('/learning')
def learning():
    return render_template('learning.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    selected_attacks = request.form.getlist('attacks')
    
    config_path = os.path.join(parent_dir, 'config', 'scanner_config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    def log_progress(message):
        logging.info(message)
    
    results = {}
    scanners = []
    
    log_progress(f"Starting scan on {target_url}")
    
    scanner_mapping = {
        'sql_injection': SQLInjectionScanner,
        'xss': XSSScanner,
        'xxe_injection': XXEInjectionScanner,
        'session_hijacking': SessionHijackingScanner,
        'brute_force': BruteForceScanner,
        'ssrf': SSRFScanner,
        'api_security': APISecurityScanner
    }

    for attack in selected_attacks:
        if attack in scanner_mapping:
            log_progress(f"Initializing {attack} scanner")
            scanner = scanner_mapping[attack](target_url, config)
            scanners.append(scanner)
    
    with ThreadPoolExecutor(max_workers=config.get('max_threads', 5)) as executor:
        future_to_scanner = {
            executor.submit(scanner.scan): scanner.__class__.__name__
            for scanner in scanners
        }
        
        for future in future_to_scanner:
            scanner_name = future_to_scanner[future]
            try:
                scan_result = future.result()
                results.update(scan_result)
            except Exception as e:
                results[scanner_name.lower()] = {"error": str(e)}
    
    log_progress("Scan completed")
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
