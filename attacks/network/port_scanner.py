import socket
import logging
import concurrent.futures
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        super().__init__(target_url, config)
        
        # Expanded port list with descriptions
        self.port_details = {
            # Web Services
            80: {'service': 'HTTP', 'description': 'Unencrypted web traffic', 'risk': 'Medium'},
            443: {'service': 'HTTPS', 'description': 'Encrypted web traffic', 'risk': 'Low'},
            8080: {'service': 'HTTP-ALT', 'description': 'Alternative HTTP port', 'risk': 'Medium'},
            8443: {'service': 'HTTPS-ALT', 'description': 'Alternative HTTPS port', 'risk': 'Low'},
            
            # Database Ports
            3306: {'service': 'MySQL', 'description': 'MySQL Database', 'risk': 'High'},
            5432: {'service': 'PostgreSQL', 'description': 'PostgreSQL Database', 'risk': 'High'},
            27017: {'service': 'MongoDB', 'description': 'MongoDB Database', 'risk': 'High'},
            1433: {'service': 'MSSQL', 'description': 'Microsoft SQL Server', 'risk': 'High'},
            
            # Administrative Ports
            22: {'service': 'SSH', 'description': 'Secure Shell', 'risk': 'Medium'},
            21: {'service': 'FTP', 'description': 'File Transfer Protocol', 'risk': 'High'},
            23: {'service': 'Telnet', 'description': 'Telnet Remote Access', 'risk': 'Critical'},
            3389: {'service': 'RDP', 'description': 'Remote Desktop Protocol', 'risk': 'High'},
            
            # Service Ports
            25: {'service': 'SMTP', 'description': 'Mail Server', 'risk': 'Medium'},
            53: {'service': 'DNS', 'description': 'Domain Name System', 'risk': 'Medium'},
            161: {'service': 'SNMP', 'description': 'Network Management', 'risk': 'High'},
            445: {'service': 'SMB', 'description': 'File Sharing', 'risk': 'High'},
            
            # Application Ports
            3000: {'service': 'Node.js', 'description': 'Node.js Applications', 'risk': 'Medium'},
            5000: {'service': 'Flask/Python', 'description': 'Python Web Applications', 'risk': 'Medium'},
            7000: {'service': 'Custom Apps', 'description': 'Custom Applications', 'risk': 'Medium'},
            8000: {'service': 'Dev Server', 'description': 'Development Server', 'risk': 'Medium'}
        }
        
        self.common_ports = list(self.port_details.keys()) + config.get('custom_ports', [])
        self.timeout = config.get('timeout', 1)
        self.max_workers = config.get('max_workers', 50)
        self.results = []

    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Execute port scanning task"""
        try:
            ip = task['ip']
            port = task['port']
            port_info = self.port_details.get(port, {
                'service': 'Unknown',
                'description': 'Unknown service',
                'risk': 'Unknown'
            })

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                return {
                    'type': 'Open Port',
                    'severity': port_info['risk'],
                    'port': port,
                    'service': port_info['service'],
                    'description': port_info['description'],
                    'details': f"Port {port} ({port_info['service']}) is open",
                    'recommendation': self.get_port_recommendations(port, port_info['service']),
                    'evidence': f"Successfully connected to port {port}"
                }
            return None

        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")
            return None

    def get_port_recommendations(self, port: int, service: str) -> str:
        """Get security recommendations based on port and service"""
        recommendations = {
            'HTTP': [
                "1. Enable HTTPS and redirect all HTTP traffic",
                "2. Implement security headers",
                "3. Use WAF protection"
            ],
            'HTTPS': [
                "1. Keep SSL/TLS certificates up to date",
                "2. Use strong cipher suites",
                "3. Enable HSTS"
            ],
            'MySQL': [
                "1. Restrict remote access",
                "2. Use strong authentication",
                "3. Keep database updated"
            ],
            'SSH': [
                "1. Use key-based authentication",
                "2. Disable root login",
                "3. Change default port"
            ],
            'FTP': [
                "1. Use SFTP instead",
                "2. Restrict anonymous access",
                "3. Enable encryption"
            ]
        }
        
        default_recs = [
            "1. Restrict access if not needed",
            "2. Use firewall rules",
            "3. Monitor for suspicious activity"
        ]
        
        return "\n".join(recommendations.get(service, default_recs))

    def scan(self) -> Dict:
        """Scan ports and return detailed results"""
        try:
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return {'port_scan': []}
            
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                logging.error(f"Could not resolve hostname: {hostname}")
                return {'port_scan': []}
            
            # Create tasks for concurrent scanning
            tasks = [
                {'ip': ip, 'port': port}
                for port in self.common_ports
            ]
            
            # Run concurrent scans
            scan_results = self.run_concurrent_tasks(tasks)
            valid_results = [r for r in scan_results if r]
            
            # Group results by risk level
            grouped_results = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
            
            for result in valid_results:
                risk_level = result['severity'].lower()
                if risk_level in grouped_results:
                    grouped_results[risk_level].append(result)
            
            summary = {
                'target': hostname,
                'ip': ip,
                'total_open_ports': len(valid_results),
                'risk_summary': {
                    level: len(results)
                    for level, results in grouped_results.items()
                },
                'findings': valid_results
            }
            
            return {'port_scan': summary}

        except Exception as e:
            logging.error(f"Port scanning error: {e}")
            return {'port_scan': []}