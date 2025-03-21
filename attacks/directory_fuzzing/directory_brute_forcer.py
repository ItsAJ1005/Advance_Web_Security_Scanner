import requests
import concurrent.futures
import logging
from typing import List, Dict, Any
import os
import re

class DirectoryBruteForcer:
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        """
        Initialize the Directory Brute Force Scanner
        
        :param target_url: URL to perform directory fuzzing on
        :param config: Configuration dictionary
        """
        self.target_url = target_url.rstrip('/')
        self.config = config or {}
        
        # Default wordlist path, can be overridden by config
        self.wordlist = self.config.get(
            'dir_fuzzing_wordlist', 
            os.path.join(os.path.dirname(__file__), '..', '..', 'payloads', 'dirfuzzing.txt')
        )
        
        # Logging setup
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def scan(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Perform directory fuzzing scan
        
        :return: Dictionary of discovered directories with vulnerability details
        """
        discovered_dirs = []
        
        try:
            # Read wordlist
            with open(self.wordlist, 'r') as f:
                paths = f.read().splitlines()
            
            # Concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                # Use a list to collect results
                futures = [
                    executor.submit(self._check_dir, path) 
                    for path in paths
                ]
                
                # Collect results
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
                for result in results:
                    if result:
                        discovered_dirs.append(result)
            
            # Log results
            self.logger.info(f"Directory Fuzzing completed. Found {len(discovered_dirs)} directories.")
            
            return {
                'dir_fuzzing': discovered_dirs
            }
        
        except Exception as e:
            self.logger.error(f"Directory Fuzzing error: {e}")
            return {
                'dir_fuzzing': [{
                    'payload': 'Directory Enumeration Error',
                    'vulnerable_url': 'N/A',
                    'severity': 'Low',
                    'details': str(e),
                    'recommendation': 'Check network connectivity and target URL'
                }]
            }
    
    def _check_dir(self, path: str) -> Dict[str, str]:
        """
        Check if a specific directory exists and assess potential vulnerabilities
        
        :param path: Path to check
        :return: Vulnerability details dictionary or None
        """
        url = f"{self.target_url}/{path}"
        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            # Vulnerability assessment logic
            vulnerability = self._assess_directory_vulnerability(response, url, path)
            
            return vulnerability if vulnerability else None
        
        except requests.exceptions.RequestException:
            return None
    
    def _assess_directory_vulnerability(self, response, url: str, path: str) -> Dict[str, str]:
        """
        Assess potential vulnerabilities in directory
        
        :param response: HTTP response object
        :param url: Full URL of the directory
        :param path: Directory path
        :return: Vulnerability details dictionary
        """
        # Common status codes indicating potential vulnerabilities
        if response.status_code in [200, 301, 302, 403]:
            # Detailed vulnerability assessment
            vulnerability_details = {
                'type': 'Directory Exposure',
                'payload': url,
                'http_method': 'GET',
                'vulnerable_parameter': path,
                'payload_used': path,
                'status_code': str(response.status_code),
                'severity': 'Medium',
                'evidence': f"Accessible directory: {path}",
                'details': 'Directory is publicly accessible',
                'recommendation': 'Restrict directory access, implement proper authentication'
            }
            
            # Additional checks for specific high-risk directories
            high_risk_dirs = ['admin', 'login', 'upload', 'config', '.env', '.git', 'backup']
            if any(high_risk_dir in path.lower() for high_risk_dir in high_risk_dirs):
                vulnerability_details['vulnerability_type'] = 'Sensitive Directory Exposure'
                vulnerability_details['severity'] = 'High'
                vulnerability_details['recommendation'] = 'Immediately restrict access to sensitive directories'
            
            # Check for directory listing
            if '<title>Index of' in response.text or 'Directory listing' in response.text:
                vulnerability_details['vulnerability_type'] = 'Directory Listing Enabled'
                vulnerability_details['severity'] = 'High'
                vulnerability_details['recommendation'] = 'Disable directory listing in web server configuration'
            
            return vulnerability_details
        
        return None
