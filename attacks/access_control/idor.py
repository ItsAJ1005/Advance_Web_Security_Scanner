import os, sys, time, socket, argparse, zipfile, requests, logging
from os import popen, system
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
import re
from core.base_scanner import BaseScanner

# COLOURS
from colorama import Fore, Back, Style

red = Fore.RED + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
blue = Fore.BLUE + Style.BRIGHT
purple = Fore.MAGENTA + Style.BRIGHT
cyan = Fore.CYAN + Style.BRIGHT
white = Fore.WHITE + Style.BRIGHT
no_colour = Fore.RESET + Back.RESET + Style.RESET_ALL

# SYMBOLS
ask = green + "[" + white + "?" + green + "] " + blue
success = yellow + "[" + white + "√" + yellow + "] " + green
error = blue + "[" + white + "!" + blue + "] " + red
info = yellow + "[" + white + "+" + yellow + "] " + cyan
info2 = green + "[" + white + "•" + green + "] " + purple

def logo_print(n):
    for word in n + "\n":
        sys.stdout.write(word)
        sys.stdout.flush()
        time.sleep(0.01)

def line_print(n):
    for word in n + "\n":
        sys.stdout.write(word)
        sys.stdout.flush()
        time.sleep(0.05)

banner = f"""
{red}      ________  ____  ____     _____   __
{cyan}    /  _/ __ \\/ __ \\/ __ \\   /  _/ | / /
{yellow}  / // / / / / / / /_/ /   / //  |/ / 
{blue}  _/ // /_/ / /_/ / _, _/  _/ // /|  /  
{red} /___/_____/\\____/_/ |_|  /___/_/ |_/ 
{blue}A IDOR Vulnerability Scanner Tool For Web Applications
{red}  
{yellow}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

def logo():
    global banner
    split_banner = banner.split("\n")
    for line_number in range(len(split_banner)):
        centre_banner = (split_banner[line_number]).center(
            os.get_terminal_size().columns - 4
        )
        print(centre_banner)

def exit_msg():
    line_print("\n" + info2 + green + "Thanks for using IDOR In!\n" + no_colour)
    os.system("clear")
    exit(0)

def load_endpoints():
    """Load endpoints from the idor_endpoints.txt file"""
    endpoints = []
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        endpoints_file = os.path.join(project_root, 'payloads', 'idor_endpoints.txt')
        
        with open(endpoints_file, 'r') as f:
            for line in f:
                # Skip empty lines and comments
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('For the'):
                    # Extract the endpoint part after the colon
                    if ':' in line:
                        endpoint = line.split(':')[1].strip()
                        endpoints.append(endpoint)
                    else:
                        endpoints.append(line)
    except Exception as e:
        print(error + f"Error loading endpoints file: {str(e)}")
        endpoints = [
            "/user/{user_id}/profile",
            "/order/{order_id}",
            "/api/user/{user_id}",
            "/account/{account_id}"
        ]
    return endpoints

# Test values for parameter replacement
test_values = {
    "user_id": ["1", "2", "admin", "root", "0"],
    "order_id": ["1000", "1001", "999", "0"],
    "account_id": ["12345", "54321", "00000", "99999"],
    "product_id": ["100", "101", "999", "1"],
    "default": ["1", "2", "3", "admin", "root"]
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1"
}

def test_endpoint(base_url, endpoint):
    """Test an endpoint for IDOR vulnerabilities"""
    # Extract parameter placeholders from the endpoint
    params = re.findall(r'{([^}]+)}', endpoint)
    
    if not params:
        # If no parameters found, test the endpoint as is
        full_url = urljoin(base_url, endpoint)
        test_single_url(full_url)
        return

    # Test each parameter
    for param in params:
        # Get appropriate test values based on parameter name
        values = test_values.get(param, test_values['default'])
        
        for value in values:
            # Replace the current parameter with test value
            test_endpoint = endpoint.replace(f'{{{param}}}', value)
            full_url = urljoin(base_url, test_endpoint)
            test_single_url(full_url)

def test_single_url(url):
    """Test a single URL for IDOR vulnerability"""
    try:
        # Try GET request
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        analyze_response(url, "GET", response)

        # Try POST request
        response = requests.post(url, headers=headers, timeout=10, allow_redirects=False)
        analyze_response(url, "POST", response)

    except requests.exceptions.RequestException as e:
        print(error + f"Error testing {url}: {str(e)}")

def analyze_response(url, method, response):
    """Analyze the response for potential IDOR vulnerabilities"""
    status_code = response.status_code
    
    if status_code == 200:
        # Success response - potential IDOR
        print(success + f"Potential IDOR vulnerability found!")
        print(info + f"URL: {url}")
        print(info + f"Method: {method}")
        print(info + f"Status Code: {status_code}")
        
        # Check response size
        content_length = len(response.content)
        print(info + f"Response Size: {content_length} bytes")
        
        # Look for sensitive data patterns
        check_sensitive_data(response.text)
        
    elif status_code in [401, 403]:
        # Access denied - might still be worth noting
        print(info2 + f"Access denied for {url}")
        print(info2 + f"Method: {method} | Status Code: {status_code}")
    
    elif status_code == 404:
        # Resource not found
        print(error + f"Resource not found: {url}")
    
    else:
        # Other status codes
        print(info2 + f"Unexpected response from {url}")
        print(info2 + f"Method: {method} | Status Code: {status_code}")

def check_sensitive_data(response_text):
    """Check for common sensitive data patterns in response"""
    sensitive_patterns = [
        r'password|passwd|pwd',
        r'email|mail',
        r'token|auth|key',
        r'credit|card|ccv|cvv',
        r'ssn|social|security',
        r'admin|root|sudo'
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, response_text, re.I):
            print(error + f"Potential sensitive data found matching pattern: {pattern}")

def main():
    try:
        target_url = input(ask + "Enter Your Target's URL: ")
        
        # Ensure the URL has a scheme
        if not urlparse(target_url).scheme:
            target_url = "http://" + target_url
        
        print(info + "Loading IDOR endpoints...")
        endpoints = load_endpoints()
        print(success + f"Loaded {len(endpoints)} endpoints to test")
        
        print(info + "Starting IDOR vulnerability scan...")
        for endpoint in endpoints:
            print(info2 + f"Testing endpoint: {endpoint}")
            test_endpoint(target_url, endpoint)
            
        print(success + "Scan completed!")
        
    except KeyboardInterrupt:
        print("\n" + info + "Scan interrupted by user")
    except Exception as e:
        print(error + f"An error occurred: {str(e)}")
    finally:
        exit_msg()

if __name__ == '__main__':
    try:
        os.system("clear")
        logo()
        main()
    except KeyboardInterrupt:
        exit_msg()
        
class IDORScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        """Initialize IDOR Scanner"""
        super().__init__(target_url, config)
        self.results = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }

    def scan(self) -> Dict:
        """
        Scan for IDOR vulnerabilities
        
        Returns:
            Dict: Scan results
        """
        try:
            results = []
            
            # Test common endpoints for IDOR vulnerabilities
            test_paths = [
                ('student', '/student/{}/grades', 'Student grades'),
                ('course', '/course/{}/enrollment', 'Course enrollment'),
                ('teacher', '/teacher/{}/schedule', 'Teacher schedule'),
                ('library', '/library/book/{}', 'Book details'),
                ('research', '/research-project/{}', 'Research project'),
                ('alumni', '/alumni/{}/profile', 'Alumni profile'),
                ('event', '/event/{}/registration', 'Event registration'),
                ('exam', '/exam/{}/results', 'Exam results')
            ]

            for resource_type, path_template, description in test_paths:
                for i in range(1, 4):  # Test IDs 1-3
                    path = path_template.format(i)
                    url = self.target_url.rstrip('/') + path
                    response = self.make_request(url)
                    
                    if response and response.status_code == 200:
                        results.append({
                            "type": "IDOR Vulnerability",
                            "severity": "High",
                            "url": url,
                            "method": "GET",
                            "parameter": "id",
                            "payload": f"Direct access to ID: {i}",
                            "evidence": f"Successful access with response size: {len(response.text)}",
                            "details": f"Unauthorized access to {description} through predictable ID",
                            "recommendation": "\n".join([
                                "1. Implement proper authentication and authorization checks",
                                "2. Use unpredictable IDs (UUID/GUID)",
                                "3. Validate user permissions for each access",
                                "4. Implement access control logging",
                                "5. Add rate limiting to prevent enumeration"
                            ])
                        })

            return {"idor": results}
        except Exception as e:
            logging.error(f"IDOR scanner error: {e}")
            return {"idor": []}

    def make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling
        
        Args:
            url (str): Target URL
            method (str): HTTP method
            **kwargs: Additional request parameters
            
        Returns:
            Optional[requests.Response]: Response object or None on error
        """
        try:
            kwargs['headers'] = kwargs.get('headers', self.headers)
            kwargs['timeout'] = kwargs.get('timeout', 10)
            kwargs['allow_redirects'] = kwargs.get('allow_redirects', False)
            
            response = requests.request(method, url, **kwargs)
            return response
        except Exception as e:
            logging.error(f"Request error for {url}: {e}")
            return None

    def test_endpoint(self, base_url, endpoint):
        """Test an endpoint for IDOR vulnerabilities"""
        # Extract parameter placeholders from the endpoint
        params = re.findall(r'{([^}]+)}', endpoint)
        
        if not params:
            # If no parameters found, test the endpoint as is
            full_url = urljoin(base_url, endpoint)
            self.test_single_url(full_url)
            return

        # Test each parameter
        for param in params:
            # Get appropriate test values based on parameter name
            values = test_values.get(param, test_values['default'])
            
            for value in values:
                # Replace the current parameter with test value
                test_endpoint = endpoint.replace(f'{{{param}}}', value)
                full_url = urljoin(base_url, test_endpoint)
                self.test_single_url(full_url)

    def test_single_url(self, url):
        """Test a single URL for IDOR vulnerability"""
        try:
            # Try GET request
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            self.analyze_response(url, "GET", response)

            # Try POST request
            response = requests.post(url, headers=headers, timeout=10, allow_redirects=False)
            self.analyze_response(url, "POST", response)

        except requests.exceptions.RequestException as e:
            print(error + f"Error testing {url}: {str(e)}")

    def analyze_response(self, url, method, response):
        """Analyze the response for potential IDOR vulnerabilities"""
        status_code = response.status_code
        
        if status_code == 200:
            # Success response - potential IDOR
            print(success + f"Potential IDOR vulnerability found!")
            print(info + f"URL: {url}")
            print(info + f"Method: {method}")
            print(info + f"Status Code: {status_code}")
            
            # Check response size
            content_length = len(response.content)
            print(info + f"Response Size: {content_length} bytes")
            
            # Look for sensitive data patterns
            self.check_sensitive_data(response.text)
            
            # Add to results
            self.results.append({
                'url': url,
                'method': method,
                'status_code': status_code,
                'response_size': content_length
            })
            
        elif status_code in [401, 403]:
            # Access denied - might still be worth noting
            print(info2 + f"Access denied for {url}")
            print(info2 + f"Method: {method} | Status Code: {status_code}")
        
        elif status_code == 404:
            # Resource not found
            print(error + f"Resource not found: {url}")
        
        else:
            # Other status codes
            print(info2 + f"Unexpected response from {url}")
            print(info2 + f"Method: {method} | Status Code: {status_code}")

    def check_sensitive_data(self, response_text):
        """Check for common sensitive data patterns in response"""
        sensitive_patterns = [
            r'password|passwd|pwd',
            r'email|mail',
            r'token|auth|key',
            r'credit|card|ccv|cvv',
            r'ssn|social|security',
            r'admin|root|sudo'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.I):
                print(error + f"Potential sensitive data found matching pattern: {pattern}")

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """
        Execute IDOR vulnerability test for a specific task
        
        Args:
            task (Dict): Task details containing URL and parameters to test
            
        Returns:
            Optional[Dict]: Vulnerability details if found, None otherwise
        """
        try:
            url = task.get('url')
            method = task.get('method', 'GET')
            
            response = self.make_request(url, method=method)
            if not response:
                return None
                
            # Check if we can access the resource (status code 200)
            if response.status_code == 200:
                # Extract the resource type and ID from the URL
                path_parts = urlparse(url).path.split('/')
                resource_type = path_parts[1] if len(path_parts) > 1 else 'unknown'
                resource_id = path_parts[3] if len(path_parts) > 3 else 'unknown'
                
                return {
                    "type": "IDOR Vulnerability",
                    "severity": "High",
                    "url": url,
                    "method": method,
                    "parameter": "id",
                    "payload": f"Direct access to {resource_type} ID: {resource_id}",
                    "evidence": f"Successful access with response size: {len(response.text)} bytes",
                    "details": f"Unauthorized access to {resource_type} resource through predictable ID",
                    "recommendation": "\n".join([
                        "1. Implement proper authentication and authorization checks",
                        "2. Use unpredictable IDs (UUID/GUID)",
                        "3. Validate user permissions for each access",
                        "4. Implement access control logging",
                        "5. Add rate limiting to prevent enumeration"
                    ])
                }
                
        except Exception as e:
            logging.error(f"Error in IDOR task execution: {e}")
            return None

    def scan(self) -> Dict:
        """Scan for IDOR vulnerabilities"""
        try:
            tasks = []
            
            # Test paths for different resources
            test_paths = [
                ('student', '/student/{}/grades', 'Student grades'),
                ('course', '/course/{}/enrollment', 'Course enrollment'),
                ('teacher', '/teacher/{}/schedule', 'Teacher schedule'),
                ('library', '/library/book/{}', 'Book details'),
                ('research', '/research-project/{}', 'Research project'),
                ('alumni', '/alumni/{}/profile', 'Alumni profile'),
                ('event', '/event/{}/registration', 'Event registration'),
                ('exam', '/exam/{}/results', 'Exam results')
            ]

            # Create tasks for each resource and ID
            for resource_type, path_template, description in test_paths:
                for i in range(1, 4):  # Test IDs 1-3
                    path = path_template.format(i)
                    url = self.target_url.rstrip('/') + path
                    tasks.append({
                        'url': url,
                        'method': 'GET',
                        'resource_type': resource_type,
                        'description': description
                    })

            # Run tasks concurrently
            results = self.run_concurrent_tasks(tasks)
            valid_results = [r for r in results if r is not None]

            return {'idor': valid_results}

        except Exception as e:
            logging.error(f"IDOR scanner error: {e}")
            return {'idor': []}