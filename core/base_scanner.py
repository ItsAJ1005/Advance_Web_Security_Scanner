import requests
import logging
from typing import Dict, List, Any
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        self.target_url = target_url
        self.config = config or {}
        self.session = requests.Session()
        self.results = []
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('vulnerability_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Abstract method to be implemented by specific attack scanners"""
        pass

    def _send_request(self, method: str = 'GET', 
                      path: str = '', 
                      params: Dict = None, 
                      data: Dict = None) -> requests.Response:
        """Helper method to send HTTP requests"""
        full_url = f"{self.target_url}{path}"
        try:
            response = self.session.request(
                method, 
                full_url, 
                params=params, 
                data=data
            )
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return None

    def save_results(self, results: List[Dict[str, Any]]):
        """Save scan results to a file"""
        import json
        with open(f'results/{self.__class__.__name__}_results.json', 'w') as f:
            json.dump(results, f, indent=4)