import time
import logging
import re
import random
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_scanner import BaseScanner
import requests
import json
import os
from datetime import datetime

class BruteForceScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        # Add multiple login endpoints to test
        self.login_endpoints = config.get('login_endpoints', [
            "/login",
            "/admin/login",
            "/auth/login",
            "/user/login",
            "/account/login"
        ])
        
        # Expanded credential list with more variations
        self.credentials = [
            # Default Credentials
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            # ("root", "root"),
            # ("user", "password"),
            # ("test", "test"),
            
            # Additional Common Credentials
            # ("administrator", "admin"),
            # ("administrator", "password"),
            # ("admin", "admin@123"),
            # ("admin", "password123"),
            # ("guest", "guest"),
            # ("system", "system"),
            # ("postgres", "postgres"),
            # ("mysql", "mysql"),
            
            # More complex credential combinations
            # ("admin", "Password123!"),
            # ("user", "User@2023"),
            # ("test", "Test123!"),
            # ("support", "Support2023"),
            # ("helpdesk", "Help@desk"),
        ]
        
        # Configuration parameters
        self.request_delay = config.get("request_delay", 0.1)
        self.max_attempts = config.get("max_attempts", 50)  # Increased max attempts
        self.timeout = config.get("timeout", 5)
        self.threads = config.get("threads", 15)  # Increased threads
        
        # Advanced brute force parameters
        self.username_list = list(set([cred[0] for cred in self.credentials]))
        self.password_list = list(set([cred[1] for cred in self.credentials]))
        
        # Logging setup
        self.log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
    def generate_advanced_credentials(self) -> List[tuple]:
        """Generate additional credential combinations with more variations"""
        advanced_creds = []
        
        # More comprehensive username and password variations
        username_variations = [
            lambda u: u.lower(),
            lambda u: u.upper(),
            lambda u: u + "123",
            lambda u: u + "!",
            lambda u: u + "_admin",
            lambda u: u + "_user",
        ]
        
        password_variations = [
            lambda p: p.lower(),
            lambda p: p.upper(),
            lambda p: p + "123",
            lambda p: p + "!",
            lambda p: p + "@2023",
            lambda p: "123" + p,
        ]
        
        for username in self.username_list:
            for password in self.password_list:
                for u_var in username_variations:
                    for p_var in password_variations:
                        advanced_creds.append((u_var(username), p_var(password)))
        
        return list(set(advanced_creds))
    
    def scan(self) -> Dict:
        # Combine original and advanced credentials
        all_credentials = list(set(self.credentials + self.generate_advanced_credentials()))
        random.shuffle(all_credentials)
        
        # Prepare tasks for multiple login endpoints
        tasks = []
        for endpoint in self.login_endpoints:
            tasks.extend([
                {
                    'username': username,
                    'password': password,
                    'url': self.target_url.rstrip('/') + endpoint
                } for username, password in all_credentials[:self.max_attempts]
            ])
        
        # Run concurrent tasks
        results = self.run_concurrent_tasks(tasks)
        successful_logins = [r for r in results if r]
        
        # Detailed logging
        self._log_brute_force_results(successful_logins)
        
        return {
            'brute_force': [
                {
                    **login,
                    'type': 'Brute Force Success',
                    'severity': 'High',
                    'method': 'POST',
                    'parameter': 'username, password',
                    'payload': f'username={login["username"]}&password={login["password"]}',
                    'evidence': f'Successful login with credentials',
                    'details': 'Weak credentials allowed authentication bypass',
                    'recommendation': '\n'.join([
                        '1. Implement account lockout after multiple failed attempts\n',
                        '2. Use strong password policies\n',
                        '3. Enable multi-factor authentication\n',
                        '4. Implement rate limiting\n',
                        '5. Monitor and alert on multiple failed login attempts'
                    ])
                } for login in successful_logins
            ],
            'total_attempts': len(tasks),
            'successful_attempts': len(successful_logins)
        }
    
    def _log_brute_force_results(self, successful_logins: List[Dict]):
        """Log detailed brute force results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.log_dir, f"brute_force_results_{timestamp}.json")
        
        log_data = {
            'timestamp': timestamp,
            'total_successful_logins': len(successful_logins),
            'successful_logins': successful_logins
        }
        
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        # Print to console for immediate visibility
        print("\n--- Brute Force Scan Results ---")
        for login in successful_logins:
            print(f"Vulnerable Endpoint: {login['url']}")
            print(f"Credentials: {login['username']} / {login['password']}")
            print(f"Status Code: {login.get('status_code', 'N/A')}")
            print("---")
    
    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Advanced task execution with multiple detection methods"""
        try:
            time.sleep(self.request_delay * random.uniform(0.8, 1.2))
            
            login_payloads = [
                {'username': task['username'], 'password': task['password']},
                {'user': task['username'], 'pass': task['password']},
                {'login': task['username'], 'pwd': task['password']}
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            for payload in login_payloads:
                response = requests.post(
                    task['url'], 
                    data=payload, 
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                success_indicators = [
                    response.status_code == 200,
                    response.status_code == 302,
                    'login successful' in response.text.lower(),
                    'welcome' in response.text.lower(),
                    'dashboard' in response.text.lower(),
                    len(response.text) > 500
                ]
                
                if any(success_indicators):
                    return {
                        'type': 'Successful Brute Force',
                        'severity': 'High',
                        'url': task['url'],
                        'method': 'POST',
                        'username': task['username'],
                        'password': task['password'],
                        'parameter': 'username, password',
                        'payload': json.dumps(payload),
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'evidence': f'Successful login with username: {task["username"]}',
                        'details': 'Authentication bypass achieved through credential stuffing',
                        'recommendation': '\n'.join([
                            '1. Implement account lockout after multiple failed attempts',
                            '2. Use strong password policies',
                            '3. Enable multi-factor authentication',
                            '4. Implement rate limiting',
                            '5. Monitor and alert on multiple failed login attempts'
                        ])
                    }
            
            return None
        
        except Exception as e:
            logging.error(f"Brute force task error: {e}")
            return None
