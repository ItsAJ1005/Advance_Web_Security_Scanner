import time
from abc import ABC, abstractmethod
import concurrent.futures
from typing import List, Dict, Optional
import logging
import requests
from core.utils import URLUtils, RequestUtils

class BaseScanner(ABC):
    def __init__(self, target_url: str, config: Dict):
        self.target_url = URLUtils.normalize_url(target_url)
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Security-Scanner-v1.0')
        })
        self.results = []
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('results/scanner.log'),
                logging.StreamHandler()
            ]
        )

    @abstractmethod
    def scan(self) -> Dict:
        pass

    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.config.get('request_delay', 0.5))
            return self.session.request(
                method,
                url,
                timeout=self.config.get('timeout', 30),
                **kwargs
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return None