import socket
import logging
import concurrent.futures
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):
        """
        Initialize Port Scanner
        
        Args:
            target_url (str): Target URL to scan
            config (Dict): Configuration dictionary
        """
        super().__init__(target_url, config)
        
        # Common ports to scan
        self.common_ports = [
            # Web ports
            80, 443, 8080, 8443, 
            
            # Database ports
            3306, 5432, 27017, 1433, 
            
            # Service ports
            22, 21, 25, 53, 
            
            # Application ports
            3000, 5000, 7000, 8000, 
            
            # Custom ports
            config.get('custom_ports', [])
        ]
        
        # Timeout for port connection
        self.timeout = config.get('timeout', 1)
        
        # Maximum concurrent port scans
        self.max_workers = config.get('max_workers', 50)
    
    def scan(self) -> Dict:
        """
        Scan ports for the target URL
        
        Returns:
            Dict: Scan results with open ports
        """
        try:
            # Extract hostname from URL
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            
            if not hostname:
                logging.error("Invalid target URL")
                return {'port_scan': []}
            
            # Resolve IP
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                logging.error(f"Could not resolve hostname: {hostname}")
                return {'port_scan': []}
            
            # Scan ports concurrently
            open_ports = self.scan_ports(ip)
            
            return {
                'port_scan': open_ports,
                'target_ip': ip,
                'hostname': hostname
            }
        
        except Exception as e:
            logging.error(f"Port scanning error: {e}")
            return {'port_scan': [], 'error': str(e)}
    
    def scan_ports(self, ip: str) -> List[Dict]:
        """
        Scan ports concurrently
        
        Args:
            ip (str): IP address to scan
        
        Returns:
            List[Dict]: List of open ports with details
        """
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create futures for port scanning
            futures = {
                executor.submit(self.check_port, ip, port): port 
                for port in self.common_ports
            }
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    logging.error(f"Error scanning port {port}: {e}")
        
        return open_ports
    
    def check_port(self, ip: str, port: int) -> Optional[Dict]:
        """
        Check if a specific port is open
        
        Args:
            ip (str): IP address
            port (int): Port number
        
        Returns:
            Optional[Dict]: Port details if open, else None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Attempt to determine service
                service = self.get_service_name(port)
                
                return {
                    'port': port,
                    'status': 'open',
                    'service': service
                }
            
            return None
        
        except Exception as e:
            logging.error(f"Port connection error on {port}: {e}")
            return None
    
    def get_service_name(self, port: int) -> str:
        """
        Get service name for a given port
        
        Args:
            port (int): Port number
        
        Returns:
            str: Service name
        """
        services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP Proxy',
            3000: 'Node.js',
            5000: 'Flask/Python',
            27017: 'MongoDB'
        }
        
        return services.get(port, 'Unknown')