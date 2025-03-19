import time
import threading
from abc import ABC, abstractmethod
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import logging
import requests
import re  # Add this import
from urllib.parse import urljoin, urlparse
from core.utils import URLUtils, RequestUtils

class BaseScanner(ABC):
    def __init__(self, target_url: str, config: Dict):
        # Ensure URL has schema
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        self.target_url = target_url.rstrip('/')
        
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Security-Scanner-v1.0')
        })
        self.results = []
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get('max_threads', 10)
        )
        self.timeout = config.get('timeout', 10)
        self.max_workers = config.get('max_workers', 5)
        self.max_retries = config.get('max_retries', 3)
        self.setup_logging()

        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=config.get('connection_pool_size', 20),
            pool_maxsize=config.get('connection_pool_size', 20),
            max_retries=self.max_retries
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

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
        """Make HTTP request with proper error handling and timeouts"""
        try:
            # Ensure URL has proper schema
            if not url.startswith(('http://', 'https://')):
                url = urljoin(self.target_url, url.lstrip('/'))

            # Add delay between requests
            time.sleep(self.config.get('request_delay', 0.5))
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout

            # Add default headers
            headers = {
                'User-Agent': 'Security Scanner v1.0',
                'Accept': '*/*'
            }
            if 'headers' in kwargs:
                headers.update(kwargs['headers'])
            kwargs['headers'] = headers

            response = self.session.request(method, url, **kwargs)
            return response

        except requests.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
            return None

    def run_concurrent_tasks(self, tasks: List[dict]) -> List[Dict]:
        """Run tasks concurrently with proper resource management"""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.execute_task, task) for task in tasks]
            for future in futures:
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        results.append(result)
                except Exception as e:
                    logging.error(f"Task execution error: {e}")
        return results

    @abstractmethod
    def execute_task(self, task: Dict) -> Optional[Dict]:
        """Method to be implemented by child classes"""
        pass